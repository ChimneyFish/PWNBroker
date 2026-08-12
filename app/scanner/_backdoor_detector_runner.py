#!/usr/bin/env python3
"""Standalone runner for the vendored backdoor_detector.py — invoked as a
subprocess by app/scanner/backdoor_scanner.py, never imported into the Flask
process. This is what makes the timeout in backdoor_scanner.py real: a
subprocess can be killed outright, an in-process Python call can't be.

Deliberately calls ONLY the safe, non-executing analysis phases:
scan_with_yara(), scan_hardcoded_secrets(), scan_for_vulnerabilities(),
generate_manual_review_checklist(). Never run_full_analysis() or
analyze_network_behavior() — the latter auto-executes whatever entry point
it detects in the target directory (main.py, package.json -> npm start, any
executable file, etc.) via `subprocess.Popen(cmd, shell=True, ...)` with no
sandboxing. See docs/deployment.md for the full rationale.

Also neuters _run_pip_audit(): as shipped, it calls bare `pip-audit
--format json` with no -r/project_path argument, which makes pip-audit
audit whichever Python environment it's invoked from (this process's own
venv) rather than the scanned target directory — verified directly, not
assumed. Left as a no-op rather than "fixed", since patching it to audit
the target correctly would just duplicate PwnBroker's existing OSV-based
Dependency Scanner.

Usage: runner.py <target_dir> <yara_rules_dir> <tool_dir> <output_dir>
Prints one JSON object to stdout: {"findings": [...], "checklist": [...]}
The tool's own logging goes to stderr (logging.basicConfig default), so it
never pollutes stdout.
"""
import importlib.util
import json
import sys


def main():
    if len(sys.argv) != 5:
        print(json.dumps({"error": "usage: runner.py <target_dir> <yara_rules_dir> <tool_dir> <output_dir>"}))
        sys.exit(1)

    target_dir, yara_rules_dir, tool_dir, output_dir = sys.argv[1:5]

    spec = importlib.util.spec_from_file_location(
        "vendored_backdoor_detector", f"{tool_dir}/backdoor_detector.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    # Instance method override at the class level, before instantiation —
    # see module docstring for why.
    mod.BackdoorDetector._run_pip_audit = lambda self: []

    detector = mod.BackdoorDetector(
        target_path=target_dir, output_dir=output_dir, yara_rules_dir=yara_rules_dir,
    )

    # The tool's own bundled default rules (regenerated fresh on every
    # instantiation — see backdoor_scanner.py's module docstring) fail to
    # compile as shipped, for THREE independent reasons, all verified
    # directly against the installed yara-python:
    #   1. $packet_send (suspicious_network_activity) is defined in
    #      `strings:` but never referenced in `condition:` — YARA rejects
    #      unused strings, and rejects the WHOLE FILE on the first such
    #      error, so YARA scanning is silently a no-op out of the box
    #      regardless of target content.
    #   2. $shell (backdoor_indicator) has the same unused-string problem.
    #   3. Once referenced, $shell's own regex — /bin[\/\\]?(?:sh|bash|
    #      cmd|powershell)/ — turns out to be invalid syntax for this
    #      YARA engine (confirmed via a standalone yara.compile() test);
    #      a simpler equivalent pattern compiles fine.
    # Patched narrowly rather than reproducing the tool's full rule set.
    if getattr(detector, "yara_rules", None) is None:
        sig_file = detector.yara_rules_dir / "backdoor_signatures.yar"
        if sig_file.is_file():
            text = sig_file.read_text()
            text = text.replace(
                r"$shell = /bin[\/\\]?(?:sh|bash|cmd|powershell)/",
                r"$shell = /bin\/(sh|bash|cmd|powershell)/",
            )
            text = text.replace(
                "($raw_socket and $packet_sniff) or $promiscuous",
                "($raw_socket and ($packet_sniff or $packet_send)) or $promiscuous",
            )
            text = text.replace(
                "(any of ($b1,$b2,$b3,$b4,$b5,$b6,$b7,$b8,$b9,$b10,$b11)) and",
                "(any of ($b1,$b2,$b3,$b4,$b5,$b6,$b7,$b8,$b9,$b10,$b11) or $shell) and",
            )
            sig_file.write_text(text)
            detector._load_yara_rules()

    detector.scan_with_yara()
    detector.scan_hardcoded_secrets()
    detector.scan_for_vulnerabilities()
    checklist = detector.generate_manual_review_checklist()

    findings = [f.to_dict() for f in detector.result.findings]
    print(json.dumps({"findings": findings, "checklist": checklist}))


if __name__ == "__main__":
    main()
