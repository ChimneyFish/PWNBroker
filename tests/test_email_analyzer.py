"""Tests for the email-security classifier (app/email_security/analyzer.py).
Pure functions — no DB, no network."""
from app.email_security import analyzer as a


# ── shadow IT ────────────────────────────────────────────────────────────────

def test_check_shadow_it_matches_default_keywords():
    r = a.check_shadow_it("Welcome to Notion!",
                          "Please verify your email to get started with your new workspace.",
                          "notion.so")
    assert r is not None
    assert "welcome to" in r["matched_keywords"]
    assert r["sender_domain"] == "notion.so"


def test_check_shadow_it_returns_none_without_keywords():
    assert a.check_shadow_it("Quarterly report", "See attached spreadsheet.", "corp.com") is None


def test_check_shadow_it_allowlisted_domain_suppressed():
    r = a.check_shadow_it("Welcome to Salesforce", "verify your account",
                          "salesforce.com", allowlist="salesforce.com, okta.com")
    assert r is None


def test_check_shadow_it_extra_keywords_are_additive():
    r = a.check_shadow_it("Your onboarding is complete", "nothing else here",
                          "vendor.com", extra_keywords="onboarding is complete")
    assert r is not None
    assert "onboarding is complete" in r["matched_keywords"]


# ── personal-email lookalike (DLP) ───────────────────────────────────────────

def test_check_personal_lookalike_flags_similar_local_part_on_personal_domain():
    r = a.check_personal_lookalike(
        "jane.doe@corp.com",
        ["jane.doe1985@gmail.com", "external@acme.com"],
        internal_domains={"corp.com"},
    )
    assert r is not None
    assert r["recipient_domain"] == "gmail.com"
    assert r["similarity"] >= 0.6


def test_check_personal_lookalike_ignores_internal_recipients():
    r = a.check_personal_lookalike(
        "jane.doe@corp.com", ["jane.doe@corp.com"], internal_domains={"corp.com"},
    )
    assert r is None


def test_check_personal_lookalike_ignores_dissimilar_names_on_personal_domain():
    r = a.check_personal_lookalike(
        "jane.doe@corp.com", ["completely.unrelated@gmail.com"], internal_domains={"corp.com"},
    )
    assert r is None


def test_check_personal_lookalike_ignores_non_personal_domains_even_if_similar():
    r = a.check_personal_lookalike(
        "jane.doe@corp.com", ["jane.doe@some-random-business.com"], internal_domains={"corp.com"},
    )
    assert r is None


def test_check_personal_lookalike_extra_domains_are_additive():
    r = a.check_personal_lookalike(
        "jane.doe@corp.com", ["jane.doe@qq.com"], internal_domains={"corp.com"},
        extra_personal_domains="qq.com",
    )
    assert r is not None
    assert r["recipient_domain"] == "qq.com"


# ── phishing ─────────────────────────────────────────────────────────────────

def test_check_phishing_returns_none_with_no_signals():
    assert a.check_phishing("user@example.com", "Random Sender", "hi", "", "just saying hi") is None


def test_check_phishing_detects_brand_spoofed_display_name():
    r = a.check_phishing("alerts@totally-not-ms.tk", "Microsoft Security", "hello", "", "hello")
    assert r is not None
    assert any("microsoft" in s for s in r["heuristic_signals"])
    assert r["severity"] == "low"  # single heuristic signal


def test_check_phishing_detects_link_text_href_mismatch():
    html = '<a href="http://evil.tk/login">paypal.com/login</a>'
    r = a.check_phishing("user@example.com", "Sender", "subject", html, "")
    assert r is not None
    assert any("evil.tk" in s for s in r["heuristic_signals"])


def test_check_phishing_multiple_heuristics_escalate_to_medium():
    html = '<a href="http://evil.tk/login">paypal.com/login</a>'
    r = a.check_phishing("alerts@totally-not-ms.tk", "Microsoft Security",
                         "Verify your account now", html, "action required, click here immediately")
    assert r is not None
    assert len(r["heuristic_signals"]) >= 2
    assert r["severity"] == "medium"


def test_check_phishing_reputation_hit_escalates_to_high():
    def rep(domain):
        return "malicious" if domain == "evil.tk" else "clean"
    r = a.check_phishing("user@example.com", "Sender", "hi",
                         '<a href="http://evil.tk">click</a>', "click http://evil.tk",
                         reputation_fn=rep)
    assert r is not None
    assert r["severity"] == "high"
    assert r["reputation_hits"] == [{"domain": "evil.tk", "verdict": "malicious"}]


def test_check_phishing_suspicious_reputation_is_medium_not_high():
    def rep(domain):
        return "suspicious" if domain == "shady.example" else "clean"
    r = a.check_phishing("user@example.com", "Sender", "hi",
                         '<a href="http://shady.example">click</a>', "",
                         reputation_fn=rep)
    assert r["severity"] == "medium"


def test_check_phishing_reputation_fn_exceptions_are_swallowed():
    def rep(domain):
        raise RuntimeError("network down")
    r = a.check_phishing("alerts@totally-not-ms.tk", "Microsoft Security", "hi", "", "",
                         reputation_fn=rep)
    # Heuristic signal (brand spoof) still fires even though reputation_fn blew up
    assert r is not None
    assert r["reputation_hits"] == []


# ── orchestrator ─────────────────────────────────────────────────────────────

def test_classify_message_returns_none_when_nothing_flagged():
    msg = {"sender_email": "user@corp.com", "sender_name": "User", "recipients": ["a@corp.com"],
           "subject": "lunch?", "body_html": "", "body_text": "want to get lunch"}
    assert a.classify_message(msg, "user@corp.com", "outbound", {"corp.com"}) is None


def test_classify_message_combines_all_three_categories():
    msg = {
        "sender_email": "jane.doe@corp.com", "sender_name": "Jane Doe",
        "recipients": ["jane.doe1985@gmail.com"],
        "subject": "Welcome to Notion! Verify your email",
        "body_html": "", "body_text": "verify your email to get started",
    }
    result = a.classify_message(msg, "jane.doe@corp.com", "outbound", {"corp.com"})
    assert result is not None
    assert result["is_dlp_risk"] is True
    assert result["is_shadow_it"] is True
    assert result["is_phishing_risk"] is False


def test_classify_message_dlp_only_applies_to_outbound():
    msg = {
        "sender_email": "external@othercorp.com", "sender_name": "External",
        "recipients": ["jane.doe1985@gmail.com"],
        "subject": "hi", "body_html": "", "body_text": "hi",
    }
    result = a.classify_message(msg, "jane.doe@corp.com", "inbound", {"corp.com"})
    assert result is None  # DLP check is skipped for inbound; nothing else matched


def test_classify_message_severity_takes_highest_category():
    def rep(domain):
        return "malicious"
    msg = {
        "sender_email": "jane.doe@corp.com", "sender_name": "Jane Doe",
        "recipients": ["jane.doe1985@gmail.com"],
        "subject": "Welcome! Verify your email",
        "body_html": '<a href="http://evil.tk">click</a>', "body_text": "verify your email, click http://evil.tk",
    }
    result = a.classify_message(msg, "jane.doe@corp.com", "outbound", {"corp.com"}, reputation_fn=rep)
    assert result["severity"] == "high"  # phishing (reputation hit) outranks dlp/shadow_it
