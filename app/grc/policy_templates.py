"""
Library of standard company policy templates used to bootstrap a customer's
Policy Library (GRC > Policies > Templates). Each template is boilerplate text
with a small set of {{PLACEHOLDER}} tokens that get substituted with
organization-specific values when a user generates a policy from it.

This is intentionally plain text (not a full markdown/doc engine) — headings
use "# " / "## " and lists use "- " so the same body can be rendered in HTML,
plain text, or PDF export with a trivial line-based parser.
"""

PLACEHOLDERS = ["COMPANY_NAME", "EFFECTIVE_DATE", "POLICY_OWNER", "REVIEW_CYCLE"]

DEFAULTS = {
    "COMPANY_NAME":   "[Company Name]",
    "EFFECTIVE_DATE": "[Effective Date]",
    "POLICY_OWNER":   "[Policy Owner / Role]",
    "REVIEW_CYCLE":   "Annually",
}


def render(body: str, **values) -> str:
    """Substitute {{PLACEHOLDER}} tokens in a template body."""
    merged = dict(DEFAULTS)
    merged.update({k: v for k, v in values.items() if v})
    out = body
    for key, val in merged.items():
        out = out.replace("{{" + key + "}}", val)
    return out


TEMPLATES = [
    {
        "key": "acceptable_use",
        "title": "Acceptable Use Policy",
        "category": "acceptable_use",
        "summary": "Defines acceptable and prohibited use of company IT systems, networks, email, and devices by employees and contractors.",
        "body": """# Acceptable Use Policy

**Company:** {{COMPANY_NAME}}
**Effective Date:** {{EFFECTIVE_DATE}}
**Policy Owner:** {{POLICY_OWNER}}
**Review Cycle:** {{REVIEW_CYCLE}}

## 1. Purpose
This policy defines the acceptable use of {{COMPANY_NAME}} information systems, networks, devices, and data. Its purpose is to protect employees, partners, and the company from risks associated with misuse of technology resources, including malware, legal liability, and loss of productivity.

## 2. Scope
This policy applies to all employees, contractors, interns, and third parties who use {{COMPANY_NAME}} owned or managed devices, accounts, networks, or data ("Users").

## 3. General Use
- Company systems are provided for business purposes. Incidental personal use is permitted provided it does not interfere with work duties, consume excessive resources, or violate this policy.
- Users are responsible for exercising good judgment regarding what is reasonable personal use.
- Users must lock or log off devices when unattended and use strong, unique credentials in line with the Password & Authentication Policy.

## 4. Prohibited Activities
Users must not:
- Use company systems to violate any law or third-party right (harassment, discrimination, defamation, infringement, etc.).
- Install unauthorized software, disable security controls (antivirus, endpoint protection, firewalls), or circumvent access restrictions.
- Access, store, or transmit illegal, offensive, or discriminatory material.
- Share credentials, or access accounts/data they are not authorized to use.
- Use company resources for personal commercial activity, cryptocurrency mining, or unauthorized data collection.
- Connect unapproved personal devices or removable media to company systems without authorization.
- Exfiltrate confidential or proprietary information to personal accounts or unmanaged services.

## 5. Email & Communications
- Company email and messaging tools are for business use; users must not use them to send spam, phishing content, or unencrypted sensitive data.
- Users must report suspected phishing or social engineering attempts to {{POLICY_OWNER}} immediately.

## 6. Monitoring
{{COMPANY_NAME}} reserves the right to monitor, log, and inspect use of its systems and network to the extent permitted by law, for security, legal, and operational purposes. Users should have no expectation of privacy when using company systems.

## 7. Enforcement
Violations of this policy may result in disciplinary action, up to and including termination of employment or contract, and may be reported to law enforcement where applicable.

## 8. Review
This policy is reviewed {{REVIEW_CYCLE}} by {{POLICY_OWNER}} or upon material change to the organization's technology environment.
""",
    },
    {
        "key": "information_security",
        "title": "Information Security Policy",
        "category": "general",
        "summary": "The umbrella security policy establishing management commitment, security objectives, and roles for protecting company information assets.",
        "body": """# Information Security Policy

**Company:** {{COMPANY_NAME}}
**Effective Date:** {{EFFECTIVE_DATE}}
**Policy Owner:** {{POLICY_OWNER}}
**Review Cycle:** {{REVIEW_CYCLE}}

## 1. Purpose
This policy establishes {{COMPANY_NAME}}'s commitment to protecting the confidentiality, integrity, and availability of its information assets, and sets the framework under which subordinate security policies and controls operate.

## 2. Scope
Applies to all information assets owned, leased, or managed by {{COMPANY_NAME}}, and to all employees, contractors, and third parties who access those assets.

## 3. Security Objectives
- Protect confidential, proprietary, and customer information from unauthorized access, disclosure, alteration, or destruction.
- Maintain the availability and integrity of systems supporting business operations.
- Comply with applicable legal, regulatory, and contractual security obligations.
- Continuously identify and manage information security risk.

## 4. Governance & Roles
- **Executive Management** provides resources and sponsorship for the security program.
- **{{POLICY_OWNER}}** is accountable for the design, implementation, and ongoing management of the security program, including this policy and its subordinate policies.
- **Managers** ensure their teams understand and follow security policies.
- **All personnel** are responsible for protecting information assets they access and reporting suspected security incidents.

## 5. Subordinate Policies
This policy is supported by more detailed policies covering, at minimum: Acceptable Use, Access Control, Data Classification & Handling, Data Retention & Disposal, Incident Response, Vulnerability & Patch Management, Change Management, Password & Authentication, Remote Work / BYOD, Vendor & Third-Party Risk Management, Business Continuity & Disaster Recovery, Physical Security, and Security Awareness Training.

## 6. Risk Management
{{COMPANY_NAME}} maintains a risk register and performs periodic risk assessments to identify, evaluate, and treat information security risks in proportion to their likelihood and impact.

## 7. Compliance
Failure to comply with this policy or its subordinate policies may result in disciplinary action up to and including termination, and may expose the company or individuals to legal liability.

## 8. Review
This policy and its subordinate policies are reviewed {{REVIEW_CYCLE}} by {{POLICY_OWNER}}, or following a significant security incident or organizational change.
""",
    },
    {
        "key": "access_control",
        "title": "Access Control Policy",
        "category": "access_control",
        "summary": "Governs how user access to systems and data is granted, reviewed, and revoked, based on least privilege and need-to-know.",
        "body": """# Access Control Policy

**Company:** {{COMPANY_NAME}}
**Effective Date:** {{EFFECTIVE_DATE}}
**Policy Owner:** {{POLICY_OWNER}}
**Review Cycle:** {{REVIEW_CYCLE}}

## 1. Purpose
This policy defines requirements for granting, managing, and revoking access to {{COMPANY_NAME}} systems and data to ensure only authorized individuals have access appropriate to their role.

## 2. Scope
Applies to all systems, applications, networks, and data repositories owned or operated by {{COMPANY_NAME}}, and to all employees, contractors, and third parties requiring access.

## 3. Principles
- **Least Privilege:** Users are granted the minimum access required to perform their job function.
- **Need-to-Know:** Access to confidential data is limited to individuals with a legitimate business need.
- **Segregation of Duties:** Conflicting duties (e.g., requesting and approving access) are separated where feasible.

## 4. Account Provisioning
- Access requests must be approved by the requestor's manager and, for sensitive systems, by the system/data owner.
- Accounts are created with unique identifiers; shared or generic accounts require documented justification and compensating controls.
- New hires receive access on or after their start date, scoped to their role via role-based access templates where available.

## 5. Account Review & De-provisioning
- Access rights are reviewed at least {{REVIEW_CYCLE}} by system/data owners to confirm continued business need.
- Access is revoked immediately upon termination, and promptly adjusted upon role change, per the offboarding/transfer process.
- Privileged/administrative access is reviewed at least quarterly.

## 6. Privileged Access
- Administrative accounts are separate from standard user accounts and used only when performing privileged tasks.
- Multi-factor authentication (MFA) is required for all privileged and remote access.
- All privileged access is logged and periodically reviewed by {{POLICY_OWNER}}.

## 7. Third-Party Access
External parties are granted the minimum access necessary, for a defined time period, under a signed agreement covering confidentiality and security obligations.

## 8. Enforcement
Violations of this policy may result in disciplinary action up to and including termination, and revocation of system access.

## 9. Review
This policy is reviewed {{REVIEW_CYCLE}} by {{POLICY_OWNER}}.
""",
    },
    {
        "key": "data_classification",
        "title": "Data Classification & Handling Policy",
        "category": "data_classification",
        "summary": "Establishes data classification tiers and the handling, storage, and transmission requirements for each tier.",
        "body": """# Data Classification & Handling Policy

**Company:** {{COMPANY_NAME}}
**Effective Date:** {{EFFECTIVE_DATE}}
**Policy Owner:** {{POLICY_OWNER}}
**Review Cycle:** {{REVIEW_CYCLE}}

## 1. Purpose
This policy establishes a data classification scheme so that {{COMPANY_NAME}} information is protected in a manner consistent with its sensitivity and value.

## 2. Scope
Applies to all data created, received, stored, processed, or transmitted by {{COMPANY_NAME}}, in any format or medium.

## 3. Classification Tiers
- **Public:** Information approved for public release. No handling restrictions.
- **Internal:** Information intended for internal business use. Not to be shared externally without approval.
- **Confidential:** Sensitive business, employee, or customer information. Access limited to individuals with a business need; encryption required in transit and at rest.
- **Restricted:** Highly sensitive data such as authentication secrets, regulated personal data, or payment card data. Access limited to named individuals/roles, encrypted at rest and in transit, and subject to enhanced logging and monitoring.

## 4. Ownership & Labeling
- Each data set or system has a designated data owner responsible for assigning and maintaining its classification.
- Where practical, documents and repositories are labeled with their classification level.

## 5. Handling Requirements
| Action | Internal | Confidential | Restricted |
|---|---|---|---|
| Email (internal) | Allowed | Allowed | Avoid; use approved secure transfer |
| Email (external) | Case-by-case | Encrypted / approved only | Prohibited without explicit approval |
| Removable media | Discouraged | Encrypted only | Prohibited |
| Cloud storage | Approved services | Approved services, access-controlled | Approved services, encrypted, access-logged |
| Printing | Allowed | Limited, retrieve promptly | Avoid; secure print only |

## 6. Third-Party Sharing
Confidential or Restricted data may only be shared with third parties under a signed agreement containing appropriate confidentiality and security terms, and with data owner approval.

## 7. Disposal
Data no longer needed is disposed of in accordance with the Data Retention & Disposal Policy and using methods appropriate to its classification (e.g., secure wipe or physical destruction for Restricted data).

## 8. Enforcement
Mishandling of Confidential or Restricted data may result in disciplinary action and is treated as a reportable security incident where applicable.

## 9. Review
This policy is reviewed {{REVIEW_CYCLE}} by {{POLICY_OWNER}}.
""",
    },
    {
        "key": "data_retention",
        "title": "Data Retention & Disposal Policy",
        "category": "data_retention",
        "summary": "Defines how long different categories of data are retained and the secure methods used to dispose of data at end of life.",
        "body": """# Data Retention & Disposal Policy

**Company:** {{COMPANY_NAME}}
**Effective Date:** {{EFFECTIVE_DATE}}
**Policy Owner:** {{POLICY_OWNER}}
**Review Cycle:** {{REVIEW_CYCLE}}

## 1. Purpose
This policy defines how long {{COMPANY_NAME}} retains various categories of data and how that data is securely disposed of once it is no longer needed, in support of legal, regulatory, and business requirements.

## 2. Scope
Applies to all data created or held by {{COMPANY_NAME}} in any format, including electronic records, backups, and physical documents.

## 3. Retention Principles
- Data is retained only as long as necessary to fulfill the purpose for which it was collected, or as required by law, regulation, or contract.
- Retention periods are defined per data category below; the data owner may set a shorter or longer period where justified and documented.

## 4. Default Retention Schedule
- **Financial & tax records:** 7 years, or per local statutory requirement.
- **Employee records:** Duration of employment plus 7 years, or per local labor law.
- **Customer/contract records:** Duration of relationship plus 7 years, or per contractual terms.
- **Security logs & audit trails:** Minimum 1 year, extended where required for investigations or compliance.
- **Marketing/prospect data:** Until consent is withdrawn or 2 years of inactivity, whichever is sooner.
- **Backups:** Rolling retention per backup schedule; not used to circumvent deletion obligations.

## 5. Legal Hold
Where data is subject to litigation, investigation, or regulatory inquiry, routine deletion is suspended for the affected data under a documented legal hold issued by {{POLICY_OWNER}} or legal counsel.

## 6. Secure Disposal
- Electronic data is securely deleted or cryptographically erased such that it cannot be practically reconstructed.
- Physical documents containing Confidential or Restricted data are cross-cut shredded or destroyed by a certified disposal vendor.
- Decommissioned storage media is wiped or physically destroyed prior to disposal or resale.

## 7. Responsibilities
Data owners are responsible for ensuring data under their control is retained and disposed of in line with this policy. {{POLICY_OWNER}} maintains the retention schedule and coordinates disposal activities.

## 8. Review
This policy is reviewed {{REVIEW_CYCLE}} by {{POLICY_OWNER}}.
""",
    },
    {
        "key": "incident_response",
        "title": "Incident Response Policy",
        "category": "incident_response",
        "summary": "Defines how security incidents are detected, reported, triaged, contained, and reviewed at the company.",
        "body": """# Incident Response Policy

**Company:** {{COMPANY_NAME}}
**Effective Date:** {{EFFECTIVE_DATE}}
**Policy Owner:** {{POLICY_OWNER}}
**Review Cycle:** {{REVIEW_CYCLE}}

## 1. Purpose
This policy establishes {{COMPANY_NAME}}'s approach to identifying, reporting, responding to, and recovering from information security incidents in a timely and effective manner.

## 2. Scope
Applies to all suspected or confirmed security incidents affecting {{COMPANY_NAME}} systems, data, or personnel, including those involving third parties.

## 3. Definitions
An **incident** is any event that compromises the confidentiality, integrity, or availability of information or systems, including but not limited to malware infection, unauthorized access, data breach, denial of service, or loss/theft of a device containing company data.

## 4. Reporting
- All personnel must report suspected incidents to {{POLICY_OWNER}} (or the designated security contact) immediately upon discovery.
- Reports may be made via [incident reporting channel — email/ticketing system/hotline] and should include what was observed, when, and any systems/data believed affected.

## 5. Incident Response Process
1. **Identification:** Confirm and scope the incident.
2. **Containment:** Isolate affected systems/accounts to limit further impact (short-term and long-term containment).
3. **Eradication:** Remove the root cause (malware, unauthorized access, vulnerability).
4. **Recovery:** Restore affected systems to normal operation, with monitoring for recurrence.
5. **Post-Incident Review:** Document root cause, response timeline, and lessons learned; update controls to prevent recurrence.

## 6. Severity Classification
- **Critical:** Confirmed breach of Confidential/Restricted data, or widespread system outage.
- **High:** Contained compromise of a system or account with potential for escalation.
- **Medium:** Isolated malware or policy violation with limited scope.
- **Low:** Suspicious activity requiring investigation but no confirmed compromise.

## 7. Notification Obligations
Where an incident involves personal data or other regulated information, {{POLICY_OWNER}} will assess notification obligations to affected individuals, customers, and regulators in line with applicable law and contractual commitments, and coordinate with legal counsel.

## 8. Roles & Responsibilities
{{POLICY_OWNER}} leads incident response and maintains an incident response team/contact list. All employees are responsible for prompt reporting and cooperating with investigations.

## 9. Review
This policy, and the incident response plan/runbooks it references, are tested and reviewed {{REVIEW_CYCLE}}, and after any significant incident.
""",
    },
    {
        "key": "vulnerability_management",
        "title": "Vulnerability & Patch Management Policy",
        "category": "vulnerability_management",
        "summary": "Defines how vulnerabilities are identified, prioritized, remediated, and verified across company systems.",
        "body": """# Vulnerability & Patch Management Policy

**Company:** {{COMPANY_NAME}}
**Effective Date:** {{EFFECTIVE_DATE}}
**Policy Owner:** {{POLICY_OWNER}}
**Review Cycle:** {{REVIEW_CYCLE}}

## 1. Purpose
This policy defines {{COMPANY_NAME}}'s process for identifying, assessing, and remediating security vulnerabilities and applying software patches across its technology environment.

## 2. Scope
Applies to all servers, workstations, network devices, applications, and cloud infrastructure owned or managed by {{COMPANY_NAME}}.

## 3. Vulnerability Identification
- Systems are scanned for known vulnerabilities on a recurring schedule (at minimum monthly for internal assets, and after significant infrastructure changes).
- Vulnerability intelligence (e.g., CVE feeds, vendor advisories) is monitored for issues affecting company technology.

## 4. Risk-Based Prioritization & Remediation SLAs
Remediation timelines are based on severity, informed by CVSS score, exploit availability, and asset criticality:
- **Critical:** Remediate within 7 days (or apply compensating controls immediately).
- **High:** Remediate within 30 days.
- **Medium:** Remediate within 90 days.
- **Low:** Remediate at next scheduled maintenance window.

## 5. Patch Management
- Security patches are tested where feasible and deployed via a managed patching process.
- Critical/emergency patches may bypass standard change windows per the Change Management Policy's emergency change process.
- Systems that cannot be patched (e.g., legacy/EOL systems) require a documented compensating control and risk acceptance from {{POLICY_OWNER}}.

## 6. Verification
Remediated vulnerabilities are re-scanned or otherwise verified as resolved, and results are retained as evidence.

## 7. Exceptions
Any exception to remediation SLAs must be documented, risk-assessed, time-bound, and approved by {{POLICY_OWNER}}.

## 8. Reporting
Vulnerability status is reported to management on a recurring basis, including open critical/high findings and overdue remediations.

## 9. Review
This policy is reviewed {{REVIEW_CYCLE}} by {{POLICY_OWNER}}.
""",
    },
    {
        "key": "change_management",
        "title": "Change Management Policy",
        "category": "change_management",
        "summary": "Establishes a controlled process for requesting, approving, testing, and deploying changes to production systems.",
        "body": """# Change Management Policy

**Company:** {{COMPANY_NAME}}
**Effective Date:** {{EFFECTIVE_DATE}}
**Policy Owner:** {{POLICY_OWNER}}
**Review Cycle:** {{REVIEW_CYCLE}}

## 1. Purpose
This policy establishes a consistent process for managing changes to {{COMPANY_NAME}} production systems, applications, and infrastructure to minimize risk of disruption, security incidents, and unauthorized modification.

## 2. Scope
Applies to all changes to production systems, including code deployments, infrastructure configuration, network changes, and access/permission model changes.

## 3. Change Categories
- **Standard:** Pre-approved, low-risk, routine changes following a documented procedure.
- **Normal:** Changes requiring review and approval prior to implementation.
- **Emergency:** Urgent changes needed to resolve an active incident or critical vulnerability, implemented with expedited approval and retroactive documentation.

## 4. Change Process
1. **Request:** Change is documented, including description, business justification, and affected systems.
2. **Risk Assessment:** Potential impact and rollback plan are evaluated.
3. **Approval:** Normal and emergency changes require approval from {{POLICY_OWNER}} or a designated change approver before deployment (emergency changes may be approved after implementation but must be documented promptly).
4. **Testing:** Changes are tested in a non-production environment where feasible before deployment.
5. **Implementation:** Changes are deployed during an approved window, with monitoring during and after deployment.
6. **Rollback:** A documented rollback plan is available for all normal and emergency changes.

## 5. Segregation of Duties
Where feasible, the individual implementing a change is not the sole approver of that change.

## 6. Documentation & Audit Trail
All changes are logged (who, what, when, why, approval reference) in the change tracking system, and records are retained per the Data Retention & Disposal Policy.

## 7. Enforcement
Unauthorized changes to production systems are treated as a policy violation and may be investigated as a security incident.

## 8. Review
This policy is reviewed {{REVIEW_CYCLE}} by {{POLICY_OWNER}}.
""",
    },
    {
        "key": "password_authentication",
        "title": "Password & Authentication Policy",
        "category": "password_authentication",
        "summary": "Sets requirements for password strength, multi-factor authentication, and credential management.",
        "body": """# Password & Authentication Policy

**Company:** {{COMPANY_NAME}}
**Effective Date:** {{EFFECTIVE_DATE}}
**Policy Owner:** {{POLICY_OWNER}}
**Review Cycle:** {{REVIEW_CYCLE}}

## 1. Purpose
This policy defines minimum requirements for authentication credentials used to access {{COMPANY_NAME}} systems and data.

## 2. Scope
Applies to all accounts, including user, administrative, service, and application accounts, on company-managed systems.

## 3. Password Requirements
- Minimum 12 characters, using a mix of upper/lowercase letters, numbers, and symbols, or a passphrase of equivalent strength.
- Passwords must not reuse the user's prior 5 passwords, and must not be a known-breached password (checked against a breach database where technically feasible).
- Passwords must not be shared, written down insecurely, or embedded in scripts/code in plaintext.
- Default/vendor passwords must be changed before a system is placed into service.

## 4. Multi-Factor Authentication (MFA)
- MFA is required for all remote access, administrative/privileged accounts, and access to systems holding Confidential or Restricted data.
- Approved MFA methods include authenticator apps or hardware security keys; SMS-based MFA is discouraged where a stronger option is available.

## 5. Account Lockout & Monitoring
Accounts are locked after a defined number of consecutive failed login attempts and require verified reset. Authentication logs are retained and monitored for anomalous activity.

## 6. Credential Storage
- Passwords are stored using a strong, salted hashing algorithm; they are never stored or transmitted in plaintext.
- Employees are encouraged/required to use an approved password manager for generating and storing credentials.

## 7. Service & Shared Accounts
Service account credentials are stored in an approved secrets manager, rotated on a defined schedule, and scoped to least privilege. Shared accounts require documented justification and compensating controls (e.g., checked-out credentials, enhanced logging).

## 8. Enforcement
Violations of this policy may result in disciplinary action and immediate suspension of the affected account pending investigation.

## 9. Review
This policy is reviewed {{REVIEW_CYCLE}} by {{POLICY_OWNER}}.
""",
    },
    {
        "key": "remote_work_byod",
        "title": "Remote Work & BYOD Policy",
        "category": "remote_work",
        "summary": "Sets security requirements for employees working remotely and for use of personal devices to access company resources.",
        "body": """# Remote Work & BYOD Policy

**Company:** {{COMPANY_NAME}}
**Effective Date:** {{EFFECTIVE_DATE}}
**Policy Owner:** {{POLICY_OWNER}}
**Review Cycle:** {{REVIEW_CYCLE}}

## 1. Purpose
This policy establishes security requirements for employees working remotely and for the use of personally owned devices ("BYOD") to access {{COMPANY_NAME}} systems and data.

## 2. Scope
Applies to all employees and contractors who work outside a company office and/or use personal devices to access company resources.

## 3. Remote Work Requirements
- Remote connections to company systems must use company-approved VPN or zero-trust access solutions with MFA enabled.
- Company-owned devices used remotely must have up-to-date endpoint protection, disk encryption, and automatic security updates enabled.
- Confidential or Restricted data must not be printed, downloaded, or stored on personal devices or unapproved cloud storage.
- Remote workspaces should be reasonably private; screens should be locked when the device is unattended, and sensitive calls should not be taken in public spaces.

## 4. BYOD Requirements
- Personal devices used to access company email, chat, or data must be enrolled in the company's mobile device management (MDM) solution, where required by the system being accessed.
- Enrolled devices must have a passcode/biometric lock, device encryption, and remote wipe capability enabled.
- The company may remotely wipe company data (not personal data, where technically separable) from a lost/stolen device or upon termination.
- Jailbroken or rooted devices must not be used to access company resources.

## 5. Public Wi-Fi & Networks
Use of public or untrusted Wi-Fi is discouraged; where necessary, users must connect via company VPN and avoid accessing Confidential/Restricted data on untrusted networks.

## 6. Incident Reporting
Loss or theft of any device (company-owned or personal) used to access company resources must be reported to {{POLICY_OWNER}} immediately.

## 7. Enforcement
Non-compliance may result in revocation of remote access privileges and/or disciplinary action.

## 8. Review
This policy is reviewed {{REVIEW_CYCLE}} by {{POLICY_OWNER}}.
""",
    },
    {
        "key": "vendor_risk_management",
        "title": "Vendor & Third-Party Risk Management Policy",
        "category": "vendor_management",
        "summary": "Defines the due diligence, contractual, and monitoring requirements for engaging vendors and third parties that access company data or systems.",
        "body": """# Vendor & Third-Party Risk Management Policy

**Company:** {{COMPANY_NAME}}
**Effective Date:** {{EFFECTIVE_DATE}}
**Policy Owner:** {{POLICY_OWNER}}
**Review Cycle:** {{REVIEW_CYCLE}}

## 1. Purpose
This policy establishes requirements for assessing and managing security risk introduced by vendors and other third parties that access {{COMPANY_NAME}} systems or data.

## 2. Scope
Applies to all vendors, suppliers, contractors, and service providers ("third parties") that process, store, or have access to {{COMPANY_NAME}} data or systems.

## 3. Risk Tiering
Third parties are tiered based on the sensitivity of data/systems accessed and criticality to business operations (e.g., Low / Medium / High), which determines the depth of due diligence required.

## 4. Due Diligence (Onboarding)
- Higher-tier vendors are evaluated prior to engagement, which may include review of security certifications (e.g., SOC 2, ISO 27001), a security questionnaire, and/or evidence of their own vulnerability and incident management practices.
- Contracts with third parties handling Confidential or Restricted data must include confidentiality, security, breach notification, and audit/right-to-review terms.
- Data processing agreements are executed where required by applicable privacy law.

## 5. Ongoing Monitoring
- High-tier vendors are reassessed at least {{REVIEW_CYCLE}}, including review of updated certifications/attestations and any reported incidents.
- {{POLICY_OWNER}} maintains a register of active third parties, their risk tier, and access granted.

## 6. Access Management
Third-party access to systems is provisioned per the Access Control Policy — scoped to least privilege, time-bound where possible, and revoked promptly at contract termination.

## 7. Incident Notification
Contracts require third parties to notify {{COMPANY_NAME}} without undue delay upon becoming aware of a security incident affecting company data.

## 8. Offboarding
Upon contract termination, third-party access is revoked, company data is returned or securely destroyed per contractual terms, and the vendor register is updated.

## 9. Review
This policy is reviewed {{REVIEW_CYCLE}} by {{POLICY_OWNER}}.
""",
    },
    {
        "key": "business_continuity_dr",
        "title": "Business Continuity & Disaster Recovery Policy",
        "category": "business_continuity",
        "summary": "Establishes requirements for maintaining business operations and recovering systems following a disruptive event.",
        "body": """# Business Continuity & Disaster Recovery Policy

**Company:** {{COMPANY_NAME}}
**Effective Date:** {{EFFECTIVE_DATE}}
**Policy Owner:** {{POLICY_OWNER}}
**Review Cycle:** {{REVIEW_CYCLE}}

## 1. Purpose
This policy establishes {{COMPANY_NAME}}'s framework for maintaining critical business functions and recovering IT systems in the event of a disruptive incident (natural disaster, cyberattack, infrastructure failure, etc.).

## 2. Scope
Applies to all business functions and systems deemed critical to {{COMPANY_NAME}} operations, as identified through business impact analysis.

## 3. Business Impact Analysis (BIA)
{{POLICY_OWNER}} maintains a BIA identifying critical business functions, dependencies, and target recovery objectives:
- **Recovery Time Objective (RTO):** Maximum acceptable downtime for a given system/function.
- **Recovery Point Objective (RPO):** Maximum acceptable data loss, measured in time.

## 4. Backup Requirements
- Critical systems and data are backed up on a defined schedule consistent with the RPO for that system.
- Backups are encrypted, stored in a location logically and/or physically separate from production, and tested for restorability at least {{REVIEW_CYCLE}}.

## 5. Disaster Recovery Plan
A documented disaster recovery plan defines the steps, roles, and responsibilities for restoring critical systems within their target RTO, including failover procedures, alternate processing arrangements, and communication plans.

## 6. Business Continuity Plan
A documented business continuity plan defines how critical business functions continue operating (potentially in a degraded state) during a disruption, including alternate work locations/arrangements and manual workarounds where applicable.

## 7. Testing
The disaster recovery and business continuity plans are tested at least {{REVIEW_CYCLE}} (e.g., tabletop exercise, failover test, or full simulation), with results documented and gaps remediated.

## 8. Crisis Communication
{{POLICY_OWNER}} maintains an up-to-date contact list and communication plan for notifying employees, customers, and other stakeholders during a disruptive event, consistent with the Incident Response Policy where the event is security-related.

## 9. Review
This policy and its associated plans are reviewed {{REVIEW_CYCLE}}, and after any invocation or significant organizational change.
""",
    },
    {
        "key": "physical_security",
        "title": "Physical Security Policy",
        "category": "physical_security",
        "summary": "Sets requirements for securing facilities, equipment, and physical access to systems that process or store company data.",
        "body": """# Physical Security Policy

**Company:** {{COMPANY_NAME}}
**Effective Date:** {{EFFECTIVE_DATE}}
**Policy Owner:** {{POLICY_OWNER}}
**Review Cycle:** {{REVIEW_CYCLE}}

## 1. Purpose
This policy establishes requirements for physically securing {{COMPANY_NAME}} facilities, equipment, and media that store or process company data.

## 2. Scope
Applies to all company-owned or leased facilities, data centers/server rooms, and physical media containing company data.

## 3. Facility Access Control
- Access to office facilities is controlled via badge, key, or equivalent mechanism; visitors are signed in, escorted, or otherwise identified while on premises.
- Access to server rooms, network closets, and other sensitive areas is restricted to authorized personnel only and logged.
- Facility access lists are reviewed at least {{REVIEW_CYCLE}}, and access is revoked promptly upon termination.

## 4. Equipment Security
- Workstations and laptops are secured with cable locks or stored in locked areas when not in use, where practical.
- Screens must be locked when unattended, consistent with the Acceptable Use Policy.
- Portable devices and removable media containing Confidential or Restricted data are encrypted and stored securely.

## 5. Environmental Controls
Server rooms and data centers (owned or operated on the company's behalf) maintain appropriate environmental controls (fire suppression, temperature/humidity control, uninterruptible power) consistent with the criticality of the systems housed.

## 6. Media Handling & Disposal
Physical media (drives, backup tapes, printed documents) is labeled per its data classification, stored securely, and disposed of per the Data Retention & Disposal Policy.

## 7. Visitor & Vendor Access
Visitors, contractors, and vendors requiring facility access are pre-authorized, verified upon arrival, and escorted while in non-public areas unless otherwise authorized.

## 8. Incident Reporting
Any suspected unauthorized physical access, tailgating, lost badge, or missing equipment must be reported to {{POLICY_OWNER}} immediately.

## 9. Review
This policy is reviewed {{REVIEW_CYCLE}} by {{POLICY_OWNER}}.
""",
    },
    {
        "key": "security_awareness_training",
        "title": "Security Awareness Training Policy",
        "category": "security_awareness",
        "summary": "Establishes requirements for onboarding and recurring security awareness training for all personnel.",
        "body": """# Security Awareness Training Policy

**Company:** {{COMPANY_NAME}}
**Effective Date:** {{EFFECTIVE_DATE}}
**Policy Owner:** {{POLICY_OWNER}}
**Review Cycle:** {{REVIEW_CYCLE}}

## 1. Purpose
This policy establishes requirements for security awareness training to ensure all personnel understand their responsibilities in protecting {{COMPANY_NAME}} information assets.

## 2. Scope
Applies to all employees, contractors, and interns with access to {{COMPANY_NAME}} systems or data.

## 3. Onboarding Training
All new personnel complete security awareness training as part of onboarding, before or promptly after receiving system access, covering at minimum:
- This Information Security Policy and key subordinate policies (Acceptable Use, Data Classification, Password & Authentication).
- Phishing and social engineering recognition.
- Incident reporting procedures.

## 4. Recurring Training
- All personnel complete refresher security awareness training at least {{REVIEW_CYCLE}}.
- Personnel in privileged or high-risk roles (e.g., engineering, IT administration, finance) receive role-specific training addressing risks relevant to their function.

## 5. Phishing Simulations
{{COMPANY_NAME}} conducts periodic simulated phishing exercises to reinforce training and measure susceptibility; individuals who fail a simulation receive targeted follow-up training.

## 6. Tracking & Accountability
{{POLICY_OWNER}} tracks training completion, and managers are notified of overdue training for their reports. Persistent non-completion may result in restricted system access.

## 7. Policy Acknowledgment
Personnel formally acknowledge they have read and agree to comply with {{COMPANY_NAME}}'s security policies at onboarding and at each recurring training cycle.

## 8. Review
This policy is reviewed {{REVIEW_CYCLE}} by {{POLICY_OWNER}}.
""",
    },
]

_BY_KEY = {t["key"]: t for t in TEMPLATES}


def get_template(key: str):
    return _BY_KEY.get(key)


def categories():
    """Distinct categories in template order, for grouping the gallery."""
    seen = []
    for t in TEMPLATES:
        if t["category"] not in seen:
            seen.append(t["category"])
    return seen
