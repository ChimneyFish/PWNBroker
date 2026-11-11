# PWNBroker Privacy Policy

<!--
  TEMPLATE NOTICE: this is a general-purpose draft, not legal advice. Fill in
  every [BRACKETED] placeholder, check the "Our website" section against what
  your site really uses (analytics, forms, chat), and have a licensed attorney
  review it before publishing.

    [COMPANY NAME]          your company's full legal name
    [ADDRESS]               registered business address
    [PRIVACY EMAIL]         address for privacy requests (e.g. privacy@yourdomain)
    [WEBSITE]               e.g. https://pwnbroker.space
    [PAYMENT PROCESSOR]     e.g. Stripe, PayPal; or remove if you invoice directly
    [ANALYTICS PROVIDER]    e.g. Plausible, Google Analytics; or remove that bullet
    [HOSTING PROVIDER]      where the website and update server are hosted
    [RETENTION PERIOD]      how long check-in records are kept after a license ends
    [EFFECTIVE DATE] [DATE]

  Rebuild the web page after editing:  python3 scripts/build/build-docs.py --src docs/privacy.md
-->

**Effective date:** [EFFECTIVE DATE] · **Last updated:** [DATE]

## 1. Summary

PWNBroker is self-hosted software. **Your scan results, asset inventories, credentials, reports and other security data stay on your own servers. We never receive them.** We only collect what we need to sell you a license, check that it's valid, deliver updates and provide support. We do not sell personal information, and the Software sends no usage telemetry.

This Privacy Policy explains what [COMPANY NAME] ("we", "us") collects through the PWNBroker software, our update service, our website at [WEBSITE] and our support channels, and how we use it. It forms part of our [Terms of Service](terms.html).

## 2. Data that stays on your servers

Everything the Software collects or creates while you use it is stored only in your own installation. That includes:

- Scan results and vulnerability findings
- Asset and host inventories
- SSH and integration credentials
- Threat-intelligence and email-security data
- User accounts and audit logs
- Reports

You control this data ("Customer Data"). You decide how long to keep it and are responsible for handling it lawfully. We are not a processor of Customer Data, because we have no access to it.

**Third-party services you enable.** Some features contact outside services directly from your server. Examples include vulnerability databases such as NVD, OSV and GitHub Advisories; threat-intelligence feeds such as AlienVault OTX and AbuseIPDB; certificate-transparency logs; vendor changelogs; Microsoft 365 / Graph; Jira; Confluence; and your email provider. These requests go straight from your installation to the provider, using the API keys you configure. They do not pass through us. The provider's own privacy policy governs them.

## 3. Data we collect

**When you buy or renew a license:**

- Name, business email address, company name, billing address and phone number (if given)
- Order details: product, license term, number of installations, price paid and invoices

Payments are handled by [PAYMENT PROCESSOR]. We do not receive or store full card numbers.

**When your installation checks for updates or downloads an installer**, it sends your License Key to our update server. The server records:

| Data | Why |
| --- | --- |
| License ID and the customer name in the license | Confirm the license is valid and not expired |
| Installation ID (a random identifier for each install) | Enforce licenses tied to a single install, and detect misuse |
| Installed version and release channel | Offer the correct update |
| IP address | Security, abuse prevention and troubleshooting |
| Date and time of the last check | Know which installs are active and supported |

The Software checks about once an hour. Turning off automatic updates in the Software stops automatic installs, but checks continue so the Software can tell you when an update is available. To stop all check-ins, disable the updater on your server (`systemctl disable --now pwnbroker-updater.timer`). After that, we receive nothing unless you check for or download an update yourself.

**When you contact support**, we receive your name, email address and whatever you send us, such as messages, logs or screenshots. Please remove credentials and sensitive scan data before sending logs.

**When you visit our website**, our servers and [HOSTING PROVIDER] log standard request data: IP address, browser type, pages requested, referrer and time. If our website uses [ANALYTICS PROVIDER], it collects aggregated usage statistics. Cookies are limited to those needed for the site to work, plus analytics cookies where the law allows them or you have consented.

## 4. How we use it

We use personal information only to:

1. Provide, license and update the Software, and deliver installers.
2. Process payments, send invoices and manage renewals.
3. Provide support and respond to your requests.
4. Send service messages, such as license-expiry reminders, security advisories and changes to our terms. These are not marketing.
5. Send product news, but only if you opt in. You can unsubscribe at any time.
6. Detect and prevent fraud, license misuse and attacks on our services.
7. Meet legal, tax and accounting obligations, and enforce our Terms.

**Legal bases (EEA/UK).** Where the GDPR applies, we rely on:

- Performance of our contract with you, for items 1 to 4.
- Our legitimate interests in securing and improving our services, for item 6.
- Your consent, for item 5 and non-essential cookies.
- Legal obligation, for item 7.

## 5. Sharing

**We do not sell or rent personal information, and do not share it for cross-context behavioral advertising.** We share it only with:

- **Service providers** that process data on our behalf under contract: [PAYMENT PROCESSOR], [HOSTING PROVIDER], email delivery and, if used, [ANALYTICS PROVIDER]. They may use it only to provide their service to us.
- **Professional advisers**, such as lawyers, accountants and auditors, under confidentiality obligations.
- **Authorities**, when required by law or valid legal process, or when needed to protect the rights, property or safety of us, our customers or others.
- **A successor**, if we are involved in a merger, acquisition or sale of assets. This Policy, or one at least as protective, will continue to apply.

## 6. Retention and security

**Retention.**

- License and billing records: for the life of the license, then as long as tax and accounting law requires (typically up to 7 years).
- Update check-in records: while the license is active, plus [RETENTION PERIOD].
- Support conversations: up to 3 years after the last contact.
- Website logs: no more than 90 days.

After that we delete or anonymize the data.

**Security.** We protect the information we hold with access controls, encrypted connections (TLS) and signed releases, and we limit access to the people who need it. No method of storage or transmission is perfectly secure. If a breach affecting your personal information occurs, we will notify you and the relevant authorities as the law requires.

**International transfers.** We and our service providers may process data in countries other than yours, including the United States. Where the law requires, we use appropriate safeguards for those transfers, such as the European Commission's Standard Contractual Clauses.

## 7. Your rights

Depending on where you live, you may have the right to:

- Access the personal information we hold about you, and get a copy of it
- Correct inaccurate information
- Delete your information
- Restrict or object to certain processing, including direct marketing
- Port your data to another provider
- Withdraw consent at any time, where we rely on consent

**California residents** have the right to know, delete and correct personal information, and to opt out of its sale or sharing. We do not sell or share it. You will not be discriminated against for exercising these rights.

**How to make a request.** Email [PRIVACY EMAIL]. We will verify your identity and respond within the time the law requires, normally 30 days (45 days under California law). Some information we must keep, such as invoices for tax purposes, cannot be deleted until its retention period ends.

You may also complain to your local data-protection authority. We'd appreciate the chance to resolve your concern first.

## 8. Children, changes and contact

**Children.** PWNBroker is a business product. It is not directed at children under 16, and we do not knowingly collect their personal information.

**Changes.** We may update this Policy. We will post the new version at [WEBSITE]/privacy and change the "Last updated" date. For material changes, we will give notice through the Software, by email or on our website.

**Contact.** Questions or requests about privacy:

[COMPANY NAME] · [ADDRESS] · [PRIVACY EMAIL]
