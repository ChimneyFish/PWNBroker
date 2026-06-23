from datetime import datetime, timezone, timedelta
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from .extensions import db


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default="user")  # admin | user
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        return self.role == "admin"


class Target(db.Model):
    __tablename__ = "targets"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    host = db.Column(db.String(256), nullable=False)
    description = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    # SSH credentials for dependency (OSV) scanning
    target_type = db.Column(db.String(20), default="host")  # host | domain | ip
    last_enum_at = db.Column(db.DateTime)
    ssh_port = db.Column(db.Integer, default=22)
    ssh_username = db.Column(db.String(100))
    ssh_auth_type = db.Column(db.String(20), default="password")  # password | key
    ssh_password = db.Column(db.String(512))
    ssh_private_key = db.Column(db.Text)
    ssh_key_passphrase = db.Column(db.String(512))
    scans = db.relationship("Scan", backref="target", lazy="dynamic",
                            cascade="all, delete-orphan")
    domain_records = db.relationship("DomainRecord", backref="target", lazy="dynamic",
                                     cascade="all, delete-orphan")


class DomainRecord(db.Model):
    __tablename__ = "domain_records"
    id             = db.Column(db.Integer, primary_key=True)
    target_id      = db.Column(db.Integer, db.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    record_type    = db.Column(db.String(10))   # A | AAAA | CNAME | MX | NS
    name           = db.Column(db.String(512))  # DNS name / subdomain
    value          = db.Column(db.String(512))  # IP for A, target for CNAME/MX, etc.
    source         = db.Column(db.String(50))   # crt.sh | DNSDumpster
    status         = db.Column(db.String(20), default="new")  # new | active | changed | removed
    previous_value = db.Column(db.String(512))
    first_seen     = db.Column(db.DateTime)
    last_seen      = db.Column(db.DateTime)
    created_at     = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class Scan(db.Model):
    __tablename__ = "scans"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    target_id = db.Column(db.Integer, db.ForeignKey("targets.id"), nullable=False)
    scan_type = db.Column(db.String(50), default="full")  # full | port | web | cve | osv
    status = db.Column(db.String(20), default="pending")  # pending | running | done | failed
    port_range = db.Column(db.String(50), default="1-1024")
    scan_path = db.Column(db.String(512))  # filesystem path for OSV dependency scans
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    results = db.relationship("ScanResult", backref="scan", lazy="dynamic", cascade="all, delete-orphan")

    @property
    def duration(self):
        if self.started_at and self.completed_at:
            delta = self.completed_at - self.started_at
            return int(delta.total_seconds())
        return None

    @property
    def vuln_count(self):
        return self.results.filter_by(result_type="vulnerability").count()

    @property
    def critical_count(self):
        return self.results.filter_by(result_type="vulnerability", severity="critical").count()


class ScanResult(db.Model):
    __tablename__ = "scan_results"
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    result_type = db.Column(db.String(30))  # port | vulnerability | web_check | info
    host = db.Column(db.String(256))
    port = db.Column(db.Integer)
    protocol = db.Column(db.String(10))
    service = db.Column(db.String(100))
    severity = db.Column(db.String(20), default="info")  # critical | high | medium | low | info
    title = db.Column(db.String(256))
    description = db.Column(db.Text)
    cve_id = db.Column(db.String(30))
    cvss_score = db.Column(db.Float)
    remediation = db.Column(db.Text)
    fixed_version = db.Column(db.String(100))      # first version that fixes this vuln
    package_name = db.Column(db.String(200))        # dependency name (OSV scans)
    package_version = db.Column(db.String(100))     # installed version (OSV scans)
    ecosystem = db.Column(db.String(50))            # PyPI, npm, Go, etc.
    is_remediated = db.Column(db.Boolean, default=False)
    raw_data = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class ScheduledScan(db.Model):
    __tablename__ = "scheduled_scans"
    id             = db.Column(db.Integer, primary_key=True)
    name           = db.Column(db.String(120), nullable=False)
    target_id      = db.Column(db.Integer, db.ForeignKey("targets.id"), nullable=True)
    asset_group_id = db.Column(db.Integer, nullable=True)   # references asset_groups.id; added via migration
    scan_type      = db.Column(db.String(50), default="full")
    port_range     = db.Column(db.String(50), default="1-1024")
    cron_expression = db.Column(db.String(100), nullable=False)
    active     = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    last_run   = db.Column(db.DateTime)
    next_run   = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    target = db.relationship("Target", backref=db.backref("scheduled_scans", cascade="all, delete-orphan"))


class ScheduledReport(db.Model):
    __tablename__ = "scheduled_reports"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    target_id = db.Column(db.Integer, db.ForeignKey("targets.id"), nullable=True)
    recipients = db.Column(db.Text, nullable=False)  # comma-separated emails
    cron_expression = db.Column(db.String(100), nullable=False)
    report_format = db.Column(db.String(10), default="pdf")  # pdf | html
    include_resolved = db.Column(db.Boolean, default=False)
    active = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    last_sent = db.Column(db.DateTime)
    next_send = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    target = db.relationship("Target", backref="scheduled_reports")


class EmailConfig(db.Model):
    __tablename__ = "email_config"
    id = db.Column(db.Integer, primary_key=True)
    smtp_server = db.Column(db.String(256))
    smtp_port = db.Column(db.Integer, default=587)
    use_tls = db.Column(db.Boolean, default=True)
    username = db.Column(db.String(256))
    password = db.Column(db.String(256))
    sender = db.Column(db.String(256))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class CloudConfig(db.Model):
    __tablename__ = "cloud_config"
    id = db.Column(db.Integer, primary_key=True)
    enabled = db.Column(db.Boolean, default=False)
    endpoint_url = db.Column(db.String(512))
    auth_type = db.Column(db.String(20), default="bearer")  # none | bearer | api_key
    auth_token = db.Column(db.String(512))
    auth_header = db.Column(db.String(100), default="X-API-Key")
    send_file = db.Column(db.Boolean, default=True)
    file_format = db.Column(db.String(10), default="pdf")  # pdf | html
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class GeneratedReport(db.Model):
    __tablename__ = "generated_reports"
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    filename = db.Column(db.String(256), nullable=False)
    file_format = db.Column(db.String(10), default="pdf")  # pdf | html
    file_size = db.Column(db.Integer)
    delivery = db.Column(db.String(20), default="local")  # local | cloud | both
    cloud_status = db.Column(db.String(20), default="not_sent")  # not_sent | ok | error
    cloud_response = db.Column(db.Text)
    generated_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    generated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    scan = db.relationship("Scan", backref=db.backref("reports", lazy="dynamic", cascade="all, delete-orphan"))


class AtlassianConfig(db.Model):
    __tablename__ = "atlassian_config"
    id = db.Column(db.Integer, primary_key=True)
    enabled = db.Column(db.Boolean, default=False)
    base_url = db.Column(db.String(512))           # e.g. https://yourorg.atlassian.net
    email = db.Column(db.String(256))              # Atlassian account email
    api_token = db.Column(db.String(512))          # Atlassian API token
    # Confluence
    confluence_enabled = db.Column(db.Boolean, default=False)
    confluence_space_key = db.Column(db.String(50))
    confluence_parent_page_id = db.Column(db.String(50))
    # Jira
    jira_enabled = db.Column(db.Boolean, default=False)
    jira_project_key = db.Column(db.String(50))
    jira_issue_type = db.Column(db.String(50), default="Bug")
    jira_severity_threshold = db.Column(db.String(20), default="medium")  # critical|high|medium|low|info
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class ConfluencePage(db.Model):
    __tablename__ = "confluence_pages"
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    page_id = db.Column(db.String(50))
    page_url = db.Column(db.String(512))
    published_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    published_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    scan = db.relationship("Scan", backref=db.backref("confluence_pages", lazy="dynamic"))


class JiraTicket(db.Model):
    __tablename__ = "jira_tickets"
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    result_id = db.Column(db.Integer, db.ForeignKey("scan_results.id", ondelete="CASCADE"), nullable=False)
    ticket_key = db.Column(db.String(50))          # e.g. SEC-42
    ticket_url = db.Column(db.String(512))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    scan = db.relationship("Scan", backref=db.backref("jira_tickets", lazy="dynamic"))
    result = db.relationship("ScanResult", backref=db.backref("jira_tickets", lazy="dynamic"))


# ── Threat Intelligence ────────────────────────────────────────────────────────

class ThreatConfig(db.Model):
    __tablename__ = "threat_configs"
    id                      = db.Column(db.Integer, primary_key=True)
    otx_api_key             = db.Column(db.String(512))
    virustotal_api_key      = db.Column(db.String(512))
    abuseipdb_api_key       = db.Column(db.String(512))
    securitytrails_api_key  = db.Column(db.String(512))
    greynoise_api_key       = db.Column(db.String(512))
    dnsdumpster_api_key     = db.Column(db.String(512))
    nvd_api_key             = db.Column(db.String(512))
    registration_token      = db.Column(db.String(128))   # pre-shared secret for agent registration
    updated_at              = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class EndpointAgent(db.Model):
    __tablename__ = "endpoint_agents"
    id            = db.Column(db.Integer, primary_key=True)
    agent_id      = db.Column(db.String(64), unique=True, nullable=False)
    token         = db.Column(db.String(128), nullable=False)
    hostname      = db.Column(db.String(255))
    os_type       = db.Column(db.String(50))    # win32 | darwin | linux
    os_version    = db.Column(db.String(512))
    ip_address    = db.Column(db.String(45))
    status        = db.Column(db.String(20), default="unknown")   # online | offline | unknown
    last_seen     = db.Column(db.DateTime)
    registered_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    alerts        = db.relationship("AgentAlert", backref="agent", lazy="dynamic",
                                    cascade="all, delete-orphan")


class AgentAlert(db.Model):
    __tablename__ = "agent_alerts"
    id           = db.Column(db.Integer, primary_key=True)
    agent_db_id  = db.Column(db.Integer, db.ForeignKey("endpoint_agents.id"), nullable=False)
    alert_type   = db.Column(db.String(50))   # suspicious_connection | process | file_hash
    severity     = db.Column(db.String(20), default="medium")
    title        = db.Column(db.String(512))
    detail       = db.Column(db.Text)
    ioc          = db.Column(db.String(512))
    acknowledged = db.Column(db.Boolean, default=False)
    created_at   = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class SocCase(db.Model):
    __tablename__    = "soc_cases"
    id               = db.Column(db.Integer, primary_key=True)
    ioc              = db.Column(db.String(512), nullable=False)
    ioc_type         = db.Column(db.String(20))
    threat_score     = db.Column(db.Integer, default=0)
    verdict          = db.Column(db.String(20))           # suspicious | malicious
    flagging_sources = db.Column(db.Text)                 # JSON list e.g. ["VT","OTX"]
    source_count     = db.Column(db.Integer, default=0)
    otx_result       = db.Column(db.Text)
    vt_result        = db.Column(db.Text)
    abuseipdb_result = db.Column(db.Text)
    status           = db.Column(db.String(20), default="pending")  # pending|alerted|dismissed
    analyst_notes    = db.Column(db.Text)
    created_at       = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    reviewed_at      = db.Column(db.DateTime)
    reviewed_by      = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    ioc_record_id    = db.Column(db.Integer, db.ForeignKey("ioc_records.id"), nullable=True)


class IOCRecord(db.Model):
    __tablename__    = "ioc_records"
    id               = db.Column(db.Integer, primary_key=True)
    indicator        = db.Column(db.String(512), index=True, nullable=False)
    ioc_type         = db.Column(db.String(50))    # ip | domain | url | hash
    threat_score     = db.Column(db.Integer, default=0)
    verdict          = db.Column(db.String(20))    # clean | suspicious | malicious | unknown
    otx_result       = db.Column(db.Text)
    vt_result        = db.Column(db.Text)
    abuseipdb_result = db.Column(db.Text)
    looked_up_by     = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at       = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at       = db.Column(db.DateTime)


_SLA_DAYS = {"critical": 1, "high": 7, "medium": 30, "low": 90, "info": 180}


class VulnTicket(db.Model):
    __tablename__  = "vuln_tickets"
    id             = db.Column(db.Integer, primary_key=True)
    scan_result_id = db.Column(db.Integer, db.ForeignKey("scan_results.id", ondelete="CASCADE"),
                               nullable=False, unique=True)
    target_id      = db.Column(db.Integer, db.ForeignKey("targets.id", ondelete="CASCADE"),
                               nullable=False)
    title          = db.Column(db.String(300))
    vuln_name      = db.Column(db.String(300))           # human-readable vulnerability name
    host_ip        = db.Column(db.String(100))           # specific scanned device IP/hostname
    severity       = db.Column(db.String(20))
    cve_id         = db.Column(db.String(50))
    cvss_score     = db.Column(db.Float)
    description    = db.Column(db.Text)
    remediation    = db.Column(db.Text)
    scan_type      = db.Column(db.String(20))            # host | dependency
    status         = db.Column(db.String(20), default="open")
    # open | in_progress | patched | accepted_risk | false_positive
    sla_days       = db.Column(db.Integer)
    due_date       = db.Column(db.DateTime)
    opened_at      = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    patched_at     = db.Column(db.DateTime)
    assigned_to    = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    notes          = db.Column(db.Text)

    scan_result = db.relationship("ScanResult",
                                  backref=db.backref("vuln_ticket", uselist=False))
    target      = db.relationship("Target",
                                  backref=db.backref("vuln_tickets", lazy="dynamic",
                                                     cascade="all, delete-orphan"))
    assignee    = db.relationship("User", foreign_keys=[assigned_to])

    @property
    def is_resolved(self):
        return self.status in ("patched", "accepted_risk", "false_positive")

    @property
    def sla_status(self):
        if self.is_resolved:
            return "resolved"
        if not self.due_date:
            return "no_sla"
        now = datetime.now(timezone.utc)
        due = self.due_date if self.due_date.tzinfo else self.due_date.replace(tzinfo=timezone.utc)
        if due < now:
            return "overdue"
        if due < now + timedelta(days=3):
            return "due_soon"
        return "on_track"

    @property
    def days_open(self):
        start = self.opened_at or datetime.now(timezone.utc)
        end   = self.patched_at or datetime.now(timezone.utc)
        if not start.tzinfo:
            start = start.replace(tzinfo=timezone.utc)
        if not end.tzinfo:
            end = end.replace(tzinfo=timezone.utc)
        return (end - start).days

    @property
    def days_overdue(self):
        if not self.due_date or self.is_resolved:
            return 0
        now = datetime.now(timezone.utc)
        due = self.due_date if self.due_date.tzinfo else self.due_date.replace(tzinfo=timezone.utc)
        return max(0, (now - due).days)


# ── Assets ────────────────────────────────────────────────────────────────────

asset_tags = db.Table(
    "asset_tags",
    db.Column("asset_id", db.Integer, db.ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True),
    db.Column("tag_id",   db.Integer, db.ForeignKey("tags.id",   ondelete="CASCADE"), primary_key=True),
)


class Tag(db.Model):
    __tablename__ = "tags"
    id         = db.Column(db.Integer, primary_key=True)
    label      = db.Column(db.String(50), unique=True, nullable=False)
    color      = db.Column(db.String(7), default="#0bbcd4")
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class Asset(db.Model):
    __tablename__ = "assets"
    id          = db.Column(db.Integer, primary_key=True)
    ip_address  = db.Column(db.String(100), nullable=False)
    hostname    = db.Column(db.String(256))
    mac_address = db.Column(db.String(20))
    os_name     = db.Column(db.String(200))
    target_id   = db.Column(db.Integer, db.ForeignKey("targets.id", ondelete="SET NULL"), nullable=True)
    first_seen  = db.Column(db.DateTime)
    last_seen   = db.Column(db.DateTime)
    status      = db.Column(db.String(20), default="active")   # active | inactive
    notes       = db.Column(db.Text)
    created_at  = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    target = db.relationship("Target", backref="assets")
    tags   = db.relationship("Tag", secondary=asset_tags, lazy="subquery",
                             backref=db.backref("assets", lazy=True))


asset_group_members = db.Table(
    "asset_group_members",
    db.Column("group_id", db.Integer, db.ForeignKey("asset_groups.id", ondelete="CASCADE"), primary_key=True),
    db.Column("asset_id", db.Integer, db.ForeignKey("assets.id",       ondelete="CASCADE"), primary_key=True),
)


class AssetGroup(db.Model):
    __tablename__ = "asset_groups"
    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    color       = db.Column(db.String(7), default="#0bbcd4")
    group_type  = db.Column(db.String(20), default="manual")  # manual | tag | network
    tag_id      = db.Column(db.Integer, db.ForeignKey("tags.id",     ondelete="SET NULL"), nullable=True)
    target_id   = db.Column(db.Integer, db.ForeignKey("targets.id",  ondelete="SET NULL"), nullable=True)
    created_by  = db.Column(db.Integer, db.ForeignKey("users.id"),    nullable=True)
    created_at  = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    tag          = db.relationship("Tag",    foreign_keys=[tag_id])
    network      = db.relationship("Target", foreign_keys=[target_id])
    manual_assets = db.relationship("Asset", secondary=asset_group_members, lazy="subquery")


# ── CVE Enrichment (NVD + EPSS + ATT&CK) ─────────────────────────────────────

class CVEEnrichment(db.Model):
    __tablename__     = "cve_enrichments"
    id                = db.Column(db.Integer, primary_key=True)
    cve_id            = db.Column(db.String(50), unique=True, nullable=False, index=True)
    # EPSS (Exploit Prediction Scoring System)
    epss_score        = db.Column(db.Float)      # 0.0–1.0 probability of exploitation
    epss_percentile   = db.Column(db.Float)      # 0.0–1.0 relative to all CVEs
    epss_fetched_at   = db.Column(db.DateTime)
    # NVD
    cvss_v3           = db.Column(db.Float)
    cvss_v3_vector    = db.Column(db.String(100))
    cvss_v2           = db.Column(db.Float)
    nvd_severity      = db.Column(db.String(20))  # CRITICAL|HIGH|MEDIUM|LOW
    cwe_ids           = db.Column(db.Text)         # JSON list
    nvd_description   = db.Column(db.Text)
    nvd_published     = db.Column(db.DateTime)
    nvd_fetched_at    = db.Column(db.DateTime)
    # MITRE ATT&CK
    attack_techniques = db.Column(db.Text)         # JSON list of {id, name, tactic}
    attack_fetched_at = db.Column(db.DateTime)

    @property
    def epss_pct(self):
        """EPSS as 0–100 percentage string."""
        if self.epss_score is None:
            return None
        return round(self.epss_score * 100, 2)

    @property
    def risk_priority(self):
        """Composite score: CVSS × EPSS percentile for ranking."""
        cvss = self.cvss_v3 or self.cvss_v2 or 5.0
        epss = self.epss_percentile or 0.0
        return round(cvss * epss, 3)


# ── GRC ───────────────────────────────────────────────────────────────────────

_RISK_LEVELS = {
    (1, 5):  "low",
    (6, 11): "medium",
    (12, 19): "high",
    (20, 25): "critical",
}


def _risk_level(score: int) -> str:
    for (lo, hi), label in _RISK_LEVELS.items():
        if lo <= score <= hi:
            return label
    return "low"


class RiskEntry(db.Model):
    __tablename__ = "risk_entries"
    id                   = db.Column(db.Integer, primary_key=True)
    title                = db.Column(db.String(200), nullable=False)
    description          = db.Column(db.Text)
    category             = db.Column(db.String(50), default="technical")
    # technical | operational | compliance | strategic | financial
    likelihood           = db.Column(db.Integer, default=3)   # 1-5
    impact               = db.Column(db.Integer, default=3)   # 1-5
    status               = db.Column(db.String(20), default="open")
    # open | in_treatment | mitigated | accepted | transferred | closed
    owner_id             = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    asset_id             = db.Column(db.Integer, db.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    mitigation_plan      = db.Column(db.Text)
    target_date          = db.Column(db.DateTime)
    residual_likelihood  = db.Column(db.Integer)
    residual_impact      = db.Column(db.Integer)
    opened_at            = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    closed_at            = db.Column(db.DateTime)
    created_by           = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at           = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    owner = db.relationship("User", foreign_keys=[owner_id])
    asset = db.relationship("Asset", foreign_keys=[asset_id])

    @property
    def risk_score(self):
        return (self.likelihood or 1) * (self.impact or 1)

    @property
    def risk_level(self):
        return _risk_level(self.risk_score)

    @property
    def residual_score(self):
        if self.residual_likelihood and self.residual_impact:
            return self.residual_likelihood * self.residual_impact
        return None

    @property
    def residual_level(self):
        s = self.residual_score
        return _risk_level(s) if s else None

    @property
    def is_open(self):
        return self.status in ("open", "in_treatment")


class ComplianceFramework(db.Model):
    __tablename__ = "compliance_frameworks"
    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(100), nullable=False)
    short_name  = db.Column(db.String(20))
    version     = db.Column(db.String(20))
    description = db.Column(db.Text)
    created_at  = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    controls    = db.relationship("ComplianceControl", backref="framework",
                                  lazy="dynamic", cascade="all, delete-orphan")


class ComplianceControl(db.Model):
    __tablename__ = "compliance_controls"
    id           = db.Column(db.Integer, primary_key=True)
    framework_id = db.Column(db.Integer, db.ForeignKey("compliance_frameworks.id",
                                                        ondelete="CASCADE"), nullable=False)
    control_id   = db.Column(db.String(50))    # e.g. "GV.OC-01", "CIS-1"
    title        = db.Column(db.String(200), nullable=False)
    description  = db.Column(db.Text)
    category     = db.Column(db.String(100))   # Function / Domain / Clause
    assessment   = db.relationship("ControlAssessment", uselist=False,
                                   backref="control", cascade="all, delete-orphan")


class ControlAssessment(db.Model):
    __tablename__ = "control_assessments"
    id          = db.Column(db.Integer, primary_key=True)
    control_id  = db.Column(db.Integer, db.ForeignKey("compliance_controls.id",
                                                       ondelete="CASCADE"),
                            nullable=False, unique=True)
    status      = db.Column(db.String(20), default="not_assessed")
    # compliant | partial | non_compliant | not_applicable | not_assessed
    evidence    = db.Column(db.Text)
    notes       = db.Column(db.Text)
    assessed_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    assessed_at = db.Column(db.DateTime)
    next_review = db.Column(db.DateTime)

    assessor = db.relationship("User", foreign_keys=[assessed_by])


class Policy(db.Model):
    __tablename__ = "policies"
    id          = db.Column(db.Integer, primary_key=True)
    title       = db.Column(db.String(200), nullable=False)
    category    = db.Column(db.String(50), default="general")
    # access_control | data_classification | incident_response | vulnerability_management
    # change_management | acceptable_use | general
    description = db.Column(db.Text)
    version     = db.Column(db.String(20), default="1.0")
    status      = db.Column(db.String(20), default="draft")
    # draft | active | under_review | retired
    owner_id    = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    approved_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    approved_at = db.Column(db.DateTime)
    review_date = db.Column(db.DateTime)
    created_by  = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at  = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at  = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    owner    = db.relationship("User", foreign_keys=[owner_id])
    approver = db.relationship("User", foreign_keys=[approved_by])


class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id          = db.Column(db.Integer, primary_key=True)
    timestamp   = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    ip_address  = db.Column(db.String(45))
    action      = db.Column(db.String(60), index=True)
    entity_type = db.Column(db.String(40))
    entity_id   = db.Column(db.Integer)
    entity_name = db.Column(db.String(200))
    detail      = db.Column(db.Text)

    actor = db.relationship("User", foreign_keys=[user_id])


class TimeConfig(db.Model):
    __tablename__ = "time_config"
    id         = db.Column(db.Integer, primary_key=True)
    timezone   = db.Column(db.String(64),  default="UTC")
    ntp_server = db.Column(db.String(256), default="pool.ntp.org")
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class EvidenceFile(db.Model):
    __tablename__ = "evidence_files"
    id           = db.Column(db.Integer, primary_key=True)
    framework_id = db.Column(db.Integer, db.ForeignKey("compliance_frameworks.id", ondelete="CASCADE"), nullable=True)
    control_id   = db.Column(db.Integer, db.ForeignKey("compliance_controls.id",   ondelete="CASCADE"), nullable=True)
    filename     = db.Column(db.String(256), nullable=False)
    stored_name  = db.Column(db.String(256), nullable=False)
    file_size    = db.Column(db.Integer, default=0)
    mime_type    = db.Column(db.String(100))
    description  = db.Column(db.Text)
    uploaded_by  = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    uploaded_at  = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    uploader  = db.relationship("User",                foreign_keys=[uploaded_by])
    framework = db.relationship("ComplianceFramework", foreign_keys=[framework_id], backref="evidence_files")
    control   = db.relationship("ComplianceControl",   foreign_keys=[control_id],   backref="evidence_files")
