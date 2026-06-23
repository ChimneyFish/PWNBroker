"""Pre-seeded compliance framework data."""

FRAMEWORKS = [
    {
        "name": "NIST Cybersecurity Framework 2.0",
        "short_name": "NIST CSF",
        "version": "2.0",
        "description": "A voluntary framework of cybersecurity standards and best practices for managing cybersecurity risk.",
        "controls": [
            # GOVERN
            ("GV.OC-01", "Organizational Mission",          "Govern", "The organizational mission is understood and informs cybersecurity risk management."),
            ("GV.OC-02", "Internal Stakeholders",           "Govern", "Internal stakeholders with cybersecurity risk management responsibilities are identified."),
            ("GV.OC-03", "Legal Requirements",              "Govern", "Legal, regulatory, and contractual cybersecurity obligations are understood."),
            ("GV.RM-01", "Risk Management Strategy",        "Govern", "Risk management objectives are established and agreed to by organizational stakeholders."),
            ("GV.RM-02", "Risk Appetite",                   "Govern", "Risk appetite and risk tolerance statements are established, communicated, and maintained."),
            ("GV.RR-01", "Roles and Responsibilities",      "Govern", "Organizational leadership is responsible and accountable for cybersecurity risk."),
            ("GV.PO-01", "Policy Establishment",            "Govern", "Policy for managing cybersecurity risks is established based on organizational context."),
            ("GV.PO-02", "Policy Review",                   "Govern", "Policy for managing cybersecurity risks is reviewed, updated, and communicated."),
            # IDENTIFY
            ("ID.AM-01", "Asset Inventory",                 "Identify", "Inventories of hardware managed by the organization are maintained."),
            ("ID.AM-02", "Software Inventory",              "Identify", "Inventories of software, services, and systems managed by the organization are maintained."),
            ("ID.AM-05", "Asset Prioritization",            "Identify", "Assets are prioritized based on classification, criticality, resources, and impact."),
            ("ID.RA-01", "Vulnerability Identification",    "Identify", "Vulnerabilities in assets are identified, validated, and recorded."),
            ("ID.RA-02", "Threat Intelligence",             "Identify", "Cyber threat intelligence is received from information sharing forums and sources."),
            ("ID.RA-05", "Risk Register",                   "Identify", "Threats, vulnerabilities, likelihoods, and impacts are used to understand risk."),
            ("ID.IM-01", "Improvements from Assessments",   "Identify", "Improvements are identified from evaluations, assessments, and exercises."),
            # PROTECT
            ("PR.AA-01", "Identity Management",             "Protect", "Identities and credentials for authorized users, services, and hardware are managed."),
            ("PR.AA-03", "Least Privilege",                 "Protect", "Users, services, and hardware are authorized with least privilege."),
            ("PR.AT-01", "Awareness Training",              "Protect", "Personnel are provided with awareness and training so they can perform their duties."),
            ("PR.DS-01", "Data at Rest Protection",         "Protect", "The confidentiality, integrity, and availability of data-at-rest are protected."),
            ("PR.DS-02", "Data in Transit Protection",      "Protect", "The confidentiality, integrity, and availability of data-in-transit are protected."),
            ("PR.PS-01", "Security Configuration",          "Protect", "Configuration management practices are established and applied."),
            ("PR.IR-01", "Network Integrity",               "Protect", "Networks and environments are protected from unauthorized logical access and usage."),
            # DETECT
            ("DE.CM-01", "Networks Monitored",              "Detect",  "Networks and network services are monitored to find potentially adverse events."),
            ("DE.CM-03", "Personnel Activity Monitored",    "Detect",  "Personnel activity and technology usage are monitored to find potentially adverse events."),
            ("DE.CM-09", "Computing Hardware Monitored",    "Detect",  "Computing hardware and software are monitored to find potentially adverse events."),
            ("DE.AE-02", "Potentially Adverse Events",      "Detect",  "Potentially adverse events are analyzed to better characterize the events."),
            ("DE.AE-06", "Information Sharing",             "Detect",  "Information on adverse events is provided to authorized staff and tools."),
            # RESPOND
            ("RS.MA-01", "Incident Triage",                 "Respond", "The characteristics of incidents are investigated to support categorization and prioritization."),
            ("RS.MA-02", "Incident Selection",              "Respond", "Incidents are selected for analysis based on organizational criteria."),
            ("RS.AN-03", "Analysis Performed",              "Respond", "Analysis is performed to establish what has taken place during an incident."),
            ("RS.CO-02", "Internal Reporting",              "Respond", "Internal and external stakeholders are notified of incidents per policies."),
            ("RS.MI-01", "Containment",                     "Respond", "Incidents are contained."),
            ("RS.MI-02", "Eradication",                     "Respond", "Incidents are eradicated."),
            # RECOVER
            ("RC.RP-01", "Recovery Plan",                   "Recover", "The recovery portion of the incident response plan is executed once initiated."),
            ("RC.CO-03", "Recovery Communication",          "Recover", "Recovery activities and progress in restoring operational capabilities are communicated."),
            ("RC.IM-01", "Recovery Improvements",           "Recover", "Recovery from incidents follows and updates the incident recovery plan."),
        ],
    },
    {
        "name": "CIS Controls v8",
        "short_name": "CIS v8",
        "version": "8",
        "description": "Prioritized set of actions to protect organizations and data from known cyber attack vectors.",
        "controls": [
            ("CIS-01", "Inventory and Control of Enterprise Assets",          "Implementation Group 1", "Actively manage all enterprise assets to accurately know what needs to be defended."),
            ("CIS-02", "Inventory and Control of Software Assets",            "Implementation Group 1", "Actively manage all software on the network to minimize attack surface."),
            ("CIS-03", "Data Protection",                                     "Implementation Group 1", "Develop processes and technical controls to identify, classify, securely handle, retain, and dispose of data."),
            ("CIS-04", "Secure Configuration of Enterprise Assets and Software", "Implementation Group 1", "Establish and maintain the secure configuration of enterprise assets and software."),
            ("CIS-05", "Account Management",                                  "Implementation Group 1", "Use processes and tools to assign and manage authorization to credentials for user accounts."),
            ("CIS-06", "Access Control Management",                           "Implementation Group 1", "Use processes and tools to create, assign, manage, and revoke access credentials and privileges."),
            ("CIS-07", "Continuous Vulnerability Management",                 "Implementation Group 1", "Develop a plan to continuously assess and track vulnerabilities on all enterprise assets."),
            ("CIS-08", "Audit Log Management",                                "Implementation Group 1", "Collect, alert, review, and retain audit logs to detect, understand, and recover from attacks."),
            ("CIS-09", "Email and Web Browser Protections",                   "Implementation Group 1", "Improve protections and detections of threats from email and web vectors."),
            ("CIS-10", "Malware Defenses",                                    "Implementation Group 1", "Prevent or control the installation, spread, and execution of malicious applications."),
            ("CIS-11", "Data Recovery",                                       "Implementation Group 2", "Establish and maintain data recovery practices sufficient to restore in-scope enterprise assets."),
            ("CIS-12", "Network Infrastructure Management",                   "Implementation Group 2", "Establish and maintain the secure configuration of network infrastructure assets."),
            ("CIS-13", "Network Monitoring and Defense",                      "Implementation Group 2", "Operate processes and tooling to establish and maintain comprehensive network monitoring."),
            ("CIS-14", "Security Awareness and Skills Training",              "Implementation Group 1", "Establish and maintain a security awareness program to influence behavior among the workforce."),
            ("CIS-15", "Service Provider Management",                         "Implementation Group 2", "Develop a process to evaluate service providers who hold sensitive data or are responsible for critical IT platforms."),
            ("CIS-16", "Application Software Security",                       "Implementation Group 2", "Manage the security life cycle of in-house developed, hosted, or acquired software."),
            ("CIS-17", "Incident Response Management",                        "Implementation Group 1", "Establish a program to develop and maintain an incident response capability."),
            ("CIS-18", "Penetration Testing",                                 "Implementation Group 2", "Test the effectiveness and resiliency of enterprise assets through identifying and exploiting weaknesses."),
        ],
    },
    {
        "name": "ISO/IEC 27001:2022",
        "short_name": "ISO 27001",
        "version": "2022",
        "description": "International standard for information security management systems (ISMS).",
        "controls": [
            ("A.5",  "Organizational Controls",           "Information Security Controls", "Policies, roles, responsibilities, and processes to manage information security."),
            ("A.5.1", "Policies for Information Security", "Organizational Controls", "Information security policy and topic-specific policies shall be defined, approved, published, communicated, and reviewed."),
            ("A.5.2", "Information Security Roles",       "Organizational Controls", "All information security responsibilities shall be defined and allocated."),
            ("A.5.7", "Threat Intelligence",              "Organizational Controls", "Information relating to information security threats shall be collected and analyzed."),
            ("A.5.8", "IS in Project Management",         "Organizational Controls", "Information security shall be integrated into project management."),
            ("A.5.23","IS for Cloud Services",            "Organizational Controls", "Processes for acquisition, use, management, and exit from cloud services."),
            ("A.6",  "People Controls",                   "Information Security Controls", "Controls related to people and their interaction with information security."),
            ("A.6.1", "Screening",                        "People Controls", "Background verification checks shall be carried out on all candidates."),
            ("A.6.3", "IS Awareness",                     "People Controls", "Personnel shall receive appropriate information security awareness, education, and training."),
            ("A.6.8", "IS Event Reporting",               "People Controls", "Personnel shall be able to report observed or suspected information security events."),
            ("A.7",  "Physical Controls",                 "Information Security Controls", "Controls related to physical and environmental security."),
            ("A.7.1", "Physical Security Perimeters",     "Physical Controls", "Security perimeters shall be defined and used to protect sensitive areas."),
            ("A.7.4", "Physical Security Monitoring",     "Physical Controls", "Premises shall be continuously monitored for unauthorized physical access."),
            ("A.8",  "Technological Controls",            "Information Security Controls", "Controls related to technology and systems."),
            ("A.8.1", "User Endpoint Devices",            "Technological Controls", "Information stored on, processed by, or accessible via user endpoint devices shall be protected."),
            ("A.8.2", "Privileged Access Rights",         "Technological Controls", "The allocation and use of privileged access rights shall be restricted and managed."),
            ("A.8.5", "Secure Authentication",            "Technological Controls", "Secure authentication technologies and procedures shall be implemented."),
            ("A.8.7", "Protection Against Malware",       "Technological Controls", "Protection against malware shall be implemented and supported by appropriate user awareness."),
            ("A.8.8", "Management of Technical Vulnerabilities", "Technological Controls", "Information about technical vulnerabilities shall be obtained in a timely fashion."),
            ("A.8.15","Logging",                          "Technological Controls", "Logs that record activities, exceptions, faults, and other relevant events shall be produced, stored, protected, and analyzed."),
            ("A.8.16","Monitoring Activities",            "Technological Controls", "Networks, systems, and applications shall be monitored for anomalous behaviour."),
            ("A.8.25","Secure Development Lifecycle",     "Technological Controls", "Rules for the secure development of software and systems shall be established and applied."),
        ],
    },
]


def seed_frameworks(db, ComplianceFramework, ComplianceControl):
    """Seed default frameworks if not already present."""
    if ComplianceFramework.query.first():
        return
    for fw_data in FRAMEWORKS:
        fw = ComplianceFramework(
            name=fw_data["name"],
            short_name=fw_data["short_name"],
            version=fw_data["version"],
            description=fw_data["description"],
        )
        db.session.add(fw)
        db.session.flush()
        for ctrl_id, title, category, description in fw_data["controls"]:
            db.session.add(ComplianceControl(
                framework_id=fw.id,
                control_id=ctrl_id,
                title=title,
                category=category,
                description=description,
            ))
    db.session.commit()
