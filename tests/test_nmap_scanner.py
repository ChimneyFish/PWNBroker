"""Tests for app/scanner/nmap_scanner.py.

Guards against losing -Pn again: without it, nmap skips a host entirely
(not just under-scans it) whenever the host doesn't answer nmap's default
discovery probes (ICMP echo, TCP SYN 443, TCP ACK 80, ICMP timestamp) —
which a lot of real, vulnerable hosts don't, because a host firewall drops
exactly those probes while still exposing open services. That silently
shrinks "scan this subnet" down to "scan whatever answers a ping" and can
make a scan go from many findings to zero if network conditions change.
"""
from unittest.mock import MagicMock, patch

from app.scanner import nmap_scanner as ns


def _fake_scanner(all_hosts=None):
    nm = MagicMock()
    nm.all_hosts.return_value = all_hosts or []
    return nm


class TestPnFlagPresent:
    def test_subnet_scan_passes_pn(self):
        with patch.object(ns.nmap, "PortScanner", return_value=_fake_scanner()) as mock_cls:
            ns.run_port_scan("10.0.0.0/24", "1-1024")
        nm = mock_cls.return_value
        args = nm.scan.call_args.kwargs["arguments"]
        assert "-Pn" in args.split()

    def test_single_host_scan_passes_pn(self):
        with patch.object(ns.nmap, "PortScanner", return_value=_fake_scanner()) as mock_cls:
            ns.run_port_scan("10.0.0.5", "1-1024")
        nm = mock_cls.return_value
        args = nm.scan.call_args.kwargs["arguments"]
        assert "-Pn" in args.split()

    def test_web_port_scan_passes_pn(self):
        with patch.object(ns.nmap, "PortScanner", return_value=_fake_scanner()) as mock_cls:
            ns.run_web_port_scan("sub.example.test")
        nm = mock_cls.return_value
        args = nm.scan.call_args.kwargs["arguments"]
        assert "-Pn" in args.split()

    def test_single_host_scan_still_runs_vuln_scripts(self):
        with patch.object(ns.nmap, "PortScanner", return_value=_fake_scanner()) as mock_cls:
            ns.run_port_scan("10.0.0.5", "1-1024")
        args = mock_cls.return_value.scan.call_args.kwargs["arguments"]
        assert "vuln" in args

    def test_subnet_scan_skips_heavy_scripts_for_speed(self):
        with patch.object(ns.nmap, "PortScanner", return_value=_fake_scanner()) as mock_cls:
            ns.run_port_scan("10.0.0.0/24", "1-1024")
        args = mock_cls.return_value.scan.call_args.kwargs["arguments"]
        assert "--script" not in args


class TestPnBoundedByRangeSize:
    """Target host validation (app/validators.py) accepts any CIDR size, so
    -Pn — which makes nmap port-scan every address instead of skipping
    non-responders — must not be applied unboundedly, or an oversized range
    (a /16 or larger) turns into a days-long scan tying up a scan slot
    indefinitely instead of the bounded, if imperfect, default behavior."""

    def test_large_subnet_omits_pn(self):
        with patch.object(ns.nmap, "PortScanner", return_value=_fake_scanner()) as mock_cls:
            ns.run_port_scan("10.0.0.0/16", "1-1024")  # 65536 addresses
        args = mock_cls.return_value.scan.call_args.kwargs["arguments"]
        assert "-Pn" not in args.split()

    def test_small_subnet_still_gets_pn(self):
        with patch.object(ns.nmap, "PortScanner", return_value=_fake_scanner()) as mock_cls:
            ns.run_port_scan("10.0.0.0/24", "1-1024")  # 256 addresses
        args = mock_cls.return_value.scan.call_args.kwargs["arguments"]
        assert "-Pn" in args.split()

    def test_boundary_at_max_pn_addresses_is_inclusive(self):
        # /22 == 1024 addresses == _MAX_PN_ADDRESSES exactly
        with patch.object(ns.nmap, "PortScanner", return_value=_fake_scanner()) as mock_cls:
            ns.run_port_scan("10.0.0.0/22", "1-1024")
        args = mock_cls.return_value.scan.call_args.kwargs["arguments"]
        assert "-Pn" in args.split()

    def test_just_over_boundary_omits_pn(self):
        # /21 == 2048 addresses, over the cap
        with patch.object(ns.nmap, "PortScanner", return_value=_fake_scanner()) as mock_cls:
            ns.run_port_scan("10.0.0.0/21", "1-1024")
        args = mock_cls.return_value.scan.call_args.kwargs["arguments"]
        assert "-Pn" not in args.split()

    def test_large_subnet_scan_args_have_no_malformed_spacing(self):
        with patch.object(ns.nmap, "PortScanner", return_value=_fake_scanner()) as mock_cls:
            ns.run_port_scan("10.0.0.0/16", "1-1024")
        args = mock_cls.return_value.scan.call_args.kwargs["arguments"]
        assert "  " not in args
        assert args.split()[0] == "-sV"
