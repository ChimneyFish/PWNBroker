"""Classifies a normalized email message into three independent risk
categories:

- phishing:  the sender domain or a linked domain has a bad reputation
             (reusing the existing OTX/AbuseIPDB/pulseDrive threat-intel
             plumbing — see app/threat/ioc_lookup.py), or the message shows
             classic spoofing/urgency patterns even with no API keys configured.
- dlp:       an outbound message's recipient address closely resembles the
             sender's own name/address and lands on a personal webmail
             domain — i.e. "looks like the employee emailed this to themselves"
             self-forwarding / data-loss pattern.
- shadow_it: subject/body contains SaaS onboarding language ("welcome to",
             "change your password", "your free trial", ...) suggesting an
             employee signed up for a tool IT doesn't know about.

None of this touches the database or the network directly — callers pass in
a `reputation_fn(domain) -> "malicious"|"suspicious"|"clean"|"unknown"` so the
actual lookup (and its caching/corroboration) stays in ioc_lookup.py.
"""
import difflib
import re
from urllib.parse import urlparse

# ── Defaults (admin-extensible via O365Config) ──────────────────────────────

SHADOW_IT_KEYWORDS = [
    "welcome to", "verify your email", "confirm your email", "verify your account",
    "your account is ready", "activate your account", "get started with",
    "change your password", "reset your password", "your password has been reset",
    "your free trial", "trial has started", "upgrade your plan", "your subscription",
    "you've been invited to join", "has invited you to", "sign in to your new account",
    "your new workspace", "your team has been created", "invoice for your subscription",
]

PERSONAL_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com", "icloud.com",
    "me.com", "aol.com", "protonmail.com", "proton.me", "gmx.com", "mail.com",
    "yandex.com", "zoho.com", "fastmail.com", "hey.com",
}

PHISHING_URGENCY_KEYWORDS = [
    "verify your account", "unusual sign-in activity", "your account will be suspended",
    "confirm your identity", "click here immediately", "update your payment information",
    "your account has been locked", "action required", "urgent:",
    "suspicious activity detected", "your access will expire",
]

# Brand names commonly spoofed in the display name while sending from an
# unrelated domain (e.g. "Microsoft Security" <alerts@totally-not-ms.tk>).
_SPOOFABLE_BRANDS = ["microsoft", "office365", "paypal", "docusign", "apple",
                     "google", "adobe", "bankofamerica", "wellsfargo", "chase"]

_LOOKALIKE_SIMILARITY_THRESHOLD = 0.6
_URL_RE  = re.compile(r'https?://[^\s"\'<>)]+', re.IGNORECASE)
_LINK_RE = re.compile(r'<a\b[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
_TAG_RE  = re.compile(r'<[^>]+>')


# ── Helpers ───────────────────────────────────────────────────────────────────

def domain_of(address_or_url: str) -> str:
    """Return the lowercased domain from an email address, a full URL, or
    bare display text like 'paypal.com/login' (as seen in <a> link text)."""
    if not address_or_url:
        return ""
    text = address_or_url.strip()
    if "://" in text:
        return (urlparse(text).hostname or "").lower()
    if "@" in text:
        return text.rsplit("@", 1)[1].strip().lower()
    return text.split("/", 1)[0].lower()


def local_part_of(email: str) -> str:
    return email.split("@", 1)[0] if email and "@" in email else (email or "")


def _normalize_local(local: str) -> str:
    return re.sub(r'[^a-z0-9]', '', local.lower())


def strip_html(html: str) -> str:
    return _TAG_RE.sub(" ", html or "")


def extract_urls(text: str) -> list[str]:
    return _URL_RE.findall(text or "")


def extract_html_links(html: str) -> list[tuple[str, str]]:
    """Return [(href, visible_text), ...] for every anchor tag."""
    out = []
    for href, text in _LINK_RE.findall(html or ""):
        out.append((href, strip_html(text).strip()))
    return out


def _parse_domains(csv_text: str | None) -> set[str]:
    if not csv_text:
        return set()
    return {d.strip().lower() for d in csv_text.split(",") if d.strip()}


# ── Shadow IT ────────────────────────────────────────────────────────────────

def check_shadow_it(subject: str, body_text: str, sender_domain: str,
                     extra_keywords: str | None = None,
                     allowlist: str | None = None) -> dict | None:
    if sender_domain and sender_domain in _parse_domains(allowlist):
        return None

    keywords = SHADOW_IT_KEYWORDS + sorted(_parse_domains(extra_keywords))
    haystack = f"{subject or ''} {body_text or ''}".lower()
    matched = [kw for kw in keywords if kw.lower() in haystack]
    if not matched:
        return None
    return {"matched_keywords": matched, "sender_domain": sender_domain}


# ── Personal-email lookalike (DLP) ───────────────────────────────────────────

def check_personal_lookalike(sender_email: str, recipient_emails: list[str],
                              internal_domains: set[str],
                              extra_personal_domains: str | None = None) -> dict | None:
    sender_local_norm = _normalize_local(local_part_of(sender_email))
    if not sender_local_norm:
        return None
    personal_domains = PERSONAL_EMAIL_DOMAINS | _parse_domains(extra_personal_domains)

    best = None
    for recipient in recipient_emails or []:
        r_domain = domain_of(recipient)
        if not r_domain or r_domain in internal_domains or r_domain not in personal_domains:
            continue
        r_local_norm = _normalize_local(local_part_of(recipient))
        if not r_local_norm:
            continue
        ratio = difflib.SequenceMatcher(None, sender_local_norm, r_local_norm).ratio()
        contained = sender_local_norm in r_local_norm or r_local_norm in sender_local_norm
        score = max(ratio, 0.85 if contained else 0.0)
        if score >= _LOOKALIKE_SIMILARITY_THRESHOLD and (best is None or score > best["similarity"]):
            best = {
                "sender_local":    local_part_of(sender_email),
                "recipient":       recipient,
                "recipient_local": local_part_of(recipient),
                "recipient_domain": r_domain,
                "similarity":      round(score, 2),
            }
    return best


# ── Phishing ─────────────────────────────────────────────────────────────────

def _brand_spoof_signal(sender_name: str, sender_domain: str) -> str | None:
    name = (sender_name or "").lower()
    for brand in _SPOOFABLE_BRANDS:
        if brand in name and brand not in (sender_domain or ""):
            return f"Display name references '{brand}' but sender domain is '{sender_domain}'"
    return None


def _link_mismatch_signals(body_html: str) -> list[str]:
    signals = []
    for href, text in extract_html_links(body_html):
        text_domain = domain_of(text) if ("." in text and " " not in text) else ""
        href_domain = domain_of(href)
        if text_domain and href_domain and text_domain != href_domain:
            signals.append(f"Link text shows '{text_domain}' but actually points to '{href_domain}'")
    return signals


def check_phishing(sender_email: str, sender_name: str, subject: str,
                    body_html: str, body_text: str,
                    reputation_fn=None, max_reputation_checks: int = 4) -> dict | None:
    sender_domain = domain_of(sender_email)
    heuristic_signals = []

    brand_signal = _brand_spoof_signal(sender_name, sender_domain)
    if brand_signal:
        heuristic_signals.append(brand_signal)

    heuristic_signals.extend(_link_mismatch_signals(body_html))

    haystack = f"{subject or ''} {body_text or ''}".lower()
    urgency_hits = [kw for kw in PHISHING_URGENCY_KEYWORDS if kw in haystack]
    if urgency_hits:
        heuristic_signals.append(f"Urgency/credential-harvesting language: {', '.join(urgency_hits[:3])}")

    reputation_hits = []
    if reputation_fn:
        # extract_html_links pulls hrefs out of <a> tags (strip_html above would
        # discard them along with the rest of the tag); extract_urls also
        # catches bare URLs typed as plain text in either body.
        link_domains = {domain_of(href) for href, _ in extract_html_links(body_html or "")}
        link_domains |= {domain_of(u) for u in extract_urls(body_text or "") + extract_urls(body_html or "")}
        link_domains.discard("")
        link_domains.discard(sender_domain)
        candidates = [sender_domain] + sorted(link_domains)
        for domain in candidates[:max_reputation_checks]:
            if not domain:
                continue
            try:
                verdict = reputation_fn(domain)
            except Exception:
                verdict = None
            if verdict in ("malicious", "suspicious"):
                reputation_hits.append({"domain": domain, "verdict": verdict})

    if not reputation_hits and not heuristic_signals:
        return None

    if reputation_hits:
        severity = "high" if any(h["verdict"] == "malicious" for h in reputation_hits) else "medium"
    elif len(heuristic_signals) >= 2:
        severity = "medium"
    else:
        severity = "low"

    return {
        "sender_domain":     sender_domain,
        "reputation_hits":   reputation_hits,
        "heuristic_signals": heuristic_signals,
        "severity":          severity,
    }


# ── Orchestrator ─────────────────────────────────────────────────────────────

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def classify_message(message: dict, mailbox_upn: str, direction: str,
                      internal_domains: set[str], cfg=None, reputation_fn=None) -> dict | None:
    """message: {sender_email, sender_name, recipients, subject, body_html, body_text}
    Returns None if nothing was flagged, otherwise a dict with is_phishing_risk/
    is_dlp_risk/is_shadow_it booleans, their *_detail payloads, and an overall
    severity — ready to persist as an EmailScanResult."""
    body_text = message.get("body_text") or strip_html(message.get("body_html") or "")
    sender_domain = domain_of(message.get("sender_email", ""))

    phishing = check_phishing(
        message.get("sender_email", ""), message.get("sender_name", ""),
        message.get("subject", ""), message.get("body_html", ""), body_text,
        reputation_fn=reputation_fn,
    )

    dlp = None
    if direction == "outbound":
        dlp = check_personal_lookalike(
            message.get("sender_email", ""), message.get("recipients", []),
            internal_domains,
            extra_personal_domains=getattr(cfg, "personal_domains_extra", None) if cfg else None,
        )

    shadow_it = check_shadow_it(
        message.get("subject", ""), body_text, sender_domain,
        extra_keywords=getattr(cfg, "shadow_it_keywords_extra", None) if cfg else None,
        allowlist=getattr(cfg, "shadow_it_allowlist", None) if cfg else None,
    )

    if not (phishing or dlp or shadow_it):
        return None

    severity = "info"
    if phishing:
        severity = phishing["severity"]
    if dlp and _SEVERITY_RANK["medium"] > _SEVERITY_RANK[severity]:
        severity = "medium"
    if shadow_it and _SEVERITY_RANK["low"] > _SEVERITY_RANK[severity]:
        severity = "low"

    return {
        "is_phishing_risk": bool(phishing),
        "phishing_detail":  phishing,
        "is_dlp_risk":       bool(dlp),
        "dlp_detail":        dlp,
        "is_shadow_it":      bool(shadow_it),
        "shadow_it_detail":  shadow_it,
        "severity":          severity,
    }
