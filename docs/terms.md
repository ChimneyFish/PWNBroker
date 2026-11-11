# PWNBroker Terms of Service

<!--
  TEMPLATE NOTICE: this is a general-purpose draft, not legal advice. Fill in
  every [BRACKETED] placeholder and have a licensed attorney review it before
  publishing, especially the liability cap, arbitration and governing law.

    [COMPANY NAME]          your company's full legal name
    [STATE / COUNTRY]       where the company is organized (governing law)
    [COUNTY, STATE]         venue for any court action / arbitration
    [ARBITRATION PROVIDER]  e.g. the American Arbitration Association
    [ADDRESS]               registered business address
    [CONTACT EMAIL]         legal/support address for notices
    [WEBSITE]               e.g. https://pwnbroker.space
    [CURRENCY]              e.g. U.S. dollars
    [EFFECTIVE DATE] [DATE]

  Rebuild the web page after editing:  python3 scripts/build/build-docs.py --src docs/terms.md
-->

**Effective date:** [EFFECTIVE DATE] · **Last updated:** [DATE]

## 1. Acceptance of these Terms

These Terms of Service ("Terms") are a binding agreement between you and [COMPANY NAME] ("Company", "we", "us"). They govern your use of the PWNBroker software, license keys, updates, installers, documentation, website and support (together, the "Service").

By downloading, installing, activating or using the Service, or by clicking to accept these Terms, you agree to them. If you accept on behalf of an organization, you confirm you have authority to bind it, and "you" means that organization. If you do not agree, do not use the Service.

**Definitions.**

- **"Software"** means PWNBroker in object or source form, including installers, updates, patches and bundled scripts.
- **"License Key"** means the signed key we issue that enables the Software for a set term.
- **"Customer Data"** means data you or the Software collect, store or generate in your installation, including scan results, asset inventories, credentials and reports.
- **"Targets"** means any systems, networks, hosts, applications, accounts or services you scan, test or monitor with the Service.
- **"Authorized User"** means your employees and contractors whom you allow to use the Service on your behalf.

**Eligibility.** The Service is for business and professional use only. You must be at least 18 years old and legally able to enter contracts. The Service is not intended for consumers.

## 2. License grant and restrictions

The Software is licensed, not sold. Subject to these Terms and payment of applicable fees, we grant you a limited, non-exclusive, non-transferable, non-sublicensable, revocable license to install and use the Software during the License Term. You may use it only for your internal business purposes, within the scope (installations, users or assets) stated in your order or License Key.

**License Term.** Each License Key is valid for the period it states, normally one (1) year. When it expires, features that require a valid license may stop working. Expiry is not a breach by us and does not entitle you to a refund.

**License Keys.** License Keys are confidential and personal to you. Do not share, publish or resell them. We may revoke a License Key that is leaked, shared, obtained by fraud or used in breach of these Terms.

**You must not, and must not allow anyone else to:**

1. Copy, modify, translate or create derivative works of the Software, except as these Terms or an applicable open-source license expressly allow.
2. Reverse engineer, decompile or disassemble the Software, except to the extent applicable law expressly permits despite this restriction.
3. Bypass, disable, forge or tamper with License Keys, license checks, signature verification or update mechanisms.
4. Sell, rent, lease, sublicense, lend or distribute the Software, or offer it to third parties as a hosted or managed service, unless we agree in writing.
5. Remove or alter any proprietary, copyright or license notices.
6. Use the Service to build a competing product, or to benchmark it for publication without our written consent.
7. Use the Service in breach of Section 3 (Authorized use) or any applicable law.

We reserve all rights not expressly granted to you.

## 3. Authorized use only

PWNBroker is a security tool that can actively probe, scan and test systems. **You may use it only against Targets that you own, or that you have explicit, documented, written authorization to test.** You alone decide which Targets to scan and how. We do not review, approve or control your Targets.

**You represent and warrant that, for every Target:**

- You own it, or hold written permission from its owner that covers the testing you perform, its scope and its timing.
- Your use complies with all applicable laws, including computer-misuse, anti-hacking, privacy, telecommunications and export laws. Examples include the U.S. Computer Fraud and Abuse Act and the UK Computer Misuse Act.
- Your use complies with the terms of any cloud, hosting, ISP or SaaS provider whose infrastructure the Target runs on.

**Active testing risks.** Network scanning, service detection, exploit verification and credentialed checks can generate heavy traffic. They can trigger security alerts, lock accounts, degrade performance or cause outages or data loss on the Targets. You accept these risks. You are responsible for scheduling, scoping, maintenance windows, notifying stakeholders and keeping backups before scanning.

**Credentials.** If you give the Service SSH or other credentials, you confirm you are authorized to use them for testing. Use least-privilege accounts. You are responsible for storing, rotating and revoking them.

**Results are not guaranteed.** Findings, severity scores, exploit-verification results, threat-intelligence correlations and remediation advice are provided to assist you. They may contain false positives or false negatives and may miss vulnerabilities entirely. A clean result does not mean a system is secure. You must apply your own professional judgment before acting on any result.

**Prohibited uses.** You must not use the Service to:

1. Access, scan or attack any system without authorization.
2. Disrupt, damage or deny service to any network or system.
3. Develop, distribute or deploy malware, or exploit vulnerabilities for anything other than authorized testing and remediation.
4. Collect personal data unlawfully.
5. Facilitate any illegal activity.

We may suspend or terminate your license immediately, without refund, if we reasonably believe you have breached this Section. We may also cooperate with law enforcement.

## 4. Customer Data, privacy and third-party services

**You own your Customer Data.** The Software runs on infrastructure you control, and Customer Data stays in your installation. We do not access it unless you choose to send it to us, for example in a support request. You are solely responsible for its security, backup, retention and lawful processing. That includes any personal data in it and any notices or consents you need from data subjects.

**Information we do receive.** When the Software checks for or downloads updates or installers, it sends our update server your License Key, an installation ID, the installed version, the release channel and standard connection data such as IP address. We use this only to validate your license, deliver updates, prevent abuse and improve the Service. Our handling of it is described in our [Privacy Policy](privacy.html).

**Support data.** If you send us logs, screenshots or other data for support, you confirm you are allowed to share it. You should remove credentials and sensitive data first. We use it only to provide support.

**Third-party services.** The Service can connect to services you choose, such as Microsoft 365, threat-intelligence feeds, vulnerability databases and email providers. Your use of them is governed by their own terms. We are not responsible for their availability, accuracy, security or charges. You are responsible for any API keys, accounts and permissions you configure.

**Security.** We sign releases and use reasonable measures to protect our update infrastructure. No software or system is perfectly secure, and we do not guarantee the Service is free of vulnerabilities. Please report suspected security issues in the Service to [CONTACT EMAIL].

## 5. Fees, updates, support and open-source components

**Fees.** You agree to pay the fees in your order or quote. Fees are payable in advance, in [CURRENCY], and exclude taxes, which you are responsible for (other than taxes on our income). **All fees are non-refundable** except where these Terms or applicable law expressly require a refund. We may change our prices for future terms by giving at least thirty (30) days' notice before your renewal.

**Renewal.** Licenses do not renew automatically unless your order says so. To keep using licensed features, you must buy a renewal before your License Key expires.

**Updates.** During the License Term we may provide updates, patches and new versions at our discretion. We may add, change or remove features, and we are not obliged to maintain any particular feature or integration. You are responsible for installing updates and for testing them in your environment. Updates are governed by these Terms unless they come with different terms.

**Support.** Support is provided as described in your order or on [WEBSITE], on a reasonable-efforts basis unless a separate written support agreement says otherwise. We do not guarantee response or resolution times.

**Open-source and third-party components.** The Software includes or installs third-party and open-source components, such as scanning engines, templates and libraries. These are licensed to you under their own licenses, which are listed with the Software. Nothing in these Terms limits your rights under those licenses. Those components are provided "as is" by their authors, and their licenses govern your use of them. Where a component's license requires us to provide source code, contact us at [CONTACT EMAIL].

## 6. Intellectual property, feedback and confidentiality

**Our IP.** The Service, including the Software, its code, design, documentation, the PWNBroker name and logos, and all related intellectual property rights, belongs to the Company and its licensors. You may not use our trademarks without our prior written consent.

**Feedback.** If you give us suggestions, ideas or feedback, we may use them freely, without obligation or payment to you.

**Confidentiality.** Each party may receive non-public information from the other, such as License Keys, pricing, non-public product information, or Customer Data shared for support. The receiving party will:

- Use that information only to perform under these Terms.
- Protect it with at least reasonable care.
- Not disclose it except to people who need to know it and are bound by similar obligations, or where the law requires it (with prompt notice to the other party where lawful).

This does not cover information that is public through no fault of the receiving party, was already known to it, or was independently developed or lawfully received from a third party.

## 7. Disclaimers, limitation of liability and indemnification

**Disclaimer of warranties.** TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SERVICE IS PROVIDED "AS IS" AND "AS AVAILABLE", WITH ALL FAULTS AND WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS, IMPLIED OR STATUTORY. THIS INCLUDES ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, NON-INFRINGEMENT AND ACCURACY. WE DO NOT WARRANT THAT THE SERVICE WILL BE UNINTERRUPTED OR ERROR-FREE. WE DO NOT WARRANT THAT IT WILL DETECT ALL VULNERABILITIES OR THREATS, THAT ITS RESULTS WILL BE ACCURATE OR COMPLETE, OR THAT IT WILL PREVENT ANY SECURITY INCIDENT, BREACH OR LOSS. THE SERVICE DOES NOT REPLACE PROFESSIONAL SECURITY ADVICE OR A COMPREHENSIVE SECURITY PROGRAM.

**Exclusion of damages.** TO THE MAXIMUM EXTENT PERMITTED BY LAW, NEITHER THE COMPANY NOR ITS OFFICERS, EMPLOYEES, AGENTS, SUPPLIERS OR LICENSORS WILL BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, EXEMPLARY OR PUNITIVE DAMAGES. NOR WILL THEY BE LIABLE FOR LOST PROFITS, REVENUE, DATA, GOODWILL OR BUSINESS OPPORTUNITY, BUSINESS INTERRUPTION, SYSTEM DOWNTIME, OR THE COST OF SUBSTITUTE SERVICES. THIS APPLIES TO DAMAGES ARISING FROM YOUR SCANNING OR TESTING OF ANY TARGET, AND TO DAMAGES ARISING FROM ANY SECURITY INCIDENT, WHETHER OR NOT THE SERVICE DETECTED IT. IT APPLIES UNDER ANY THEORY OF LIABILITY, EVEN IF WE WERE ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

**Liability cap.** TO THE MAXIMUM EXTENT PERMITTED BY LAW, OUR TOTAL LIABILITY FOR ALL CLAIMS ARISING OUT OF OR RELATING TO THE SERVICE OR THESE TERMS WILL NOT EXCEED THE GREATER OF (A) THE FEES YOU PAID US FOR THE SERVICE IN THE TWELVE (12) MONTHS BEFORE THE EVENT GIVING RISE TO THE CLAIM, OR (B) ONE HUNDRED U.S. DOLLARS (US$100).

Some jurisdictions do not allow certain warranty exclusions or liability limits. In those jurisdictions, our liability is limited to the smallest amount the law permits.

**Indemnification.** You will defend, indemnify and hold harmless the Company and its officers, directors, employees, agents and licensors. This covers all claims, demands, losses, damages, fines, penalties, costs and expenses, including reasonable attorneys' fees, arising out of or related to:

1. Your use of the Service, including any scanning, testing or exploit verification of any Target.
2. Any claim that you lacked authorization to test a Target, or that your testing caused harm to a Target or its owner.
3. Your Customer Data, or your breach of any law or third-party right.
4. Your breach of these Terms.

We may take part in the defense with counsel of our choice at our own cost. You may not settle a claim that imposes obligations on us without our written consent.

## 8. Term, termination and general terms

**Term and termination.** These Terms apply from when you first accept them until your last License Term ends or until they are terminated. We may suspend or terminate your access and License Keys immediately if you breach these Terms, fail to pay, or use the Service unlawfully or in a way that exposes us to liability. You may stop using the Service at any time. When these Terms end, your license ends, and you must stop using and uninstall the Software. Sections 3 (as to past use), 4, 6, 7 and 8 survive termination.

**Export and sanctions.** The Service may be subject to export-control and sanctions laws, including those of the United States. You confirm you are not located in, or acting for anyone in, a sanctioned country, and are not on any government restricted-party list. You will not export, re-export or use the Service in violation of those laws.

**Governing law.** These Terms are governed by the laws of [STATE / COUNTRY], without regard to its conflict-of-laws rules. The UN Convention on Contracts for the International Sale of Goods does not apply.

**Disputes and arbitration.** Before filing any claim, the parties will try to resolve the dispute informally for thirty (30) days after written notice.

- If it is not resolved, it will be settled by binding arbitration administered by [ARBITRATION PROVIDER] under its commercial rules, before a single arbitrator in [COUNTY, STATE]. Judgment on the award may be entered in any competent court.
- **Claims must be brought individually, not as a plaintiff or class member in any class, consolidated or representative action.**
- Either party may seek injunctive relief in the courts of [COUNTY, STATE] to protect its intellectual property or confidential information, or to stop unauthorized use of the Service. You consent to those courts' jurisdiction.
- Any claim must be brought within one (1) year after it arises, where the law permits that limit.

**Changes to these Terms.** We may update these Terms from time to time. We will post the updated version at [WEBSITE]/terms and change the "Last updated" date. For material changes, we will give reasonable notice, for example through the Software, by email or on our website. If you keep using the Service after changes take effect, you accept them.

**General.**

- **Entire agreement.** These Terms, together with any order or quote and our Privacy Policy, are the entire agreement between us about the Service. If a signed order conflicts with these Terms, the order controls.
- **Severability and waiver.** If any provision is found unenforceable, it will be enforced to the maximum extent possible and the rest stays in effect. Our failure to enforce a provision is not a waiver.
- **Assignment.** You may not assign or transfer these Terms without our written consent. We may assign them in a merger, acquisition or sale of assets.
- **Force majeure.** Neither party is liable for delays or failures caused by events beyond its reasonable control (other than payment obligations).
- **Independent parties.** Nothing in these Terms creates a partnership, joint venture, agency or employment relationship.
- **Notices.** We may give notices through the Software, by email to your account contact, or on our website. Send notices to us at [CONTACT EMAIL] or [ADDRESS].

## Contact

[COMPANY NAME] · [ADDRESS] · [CONTACT EMAIL] · [WEBSITE]
