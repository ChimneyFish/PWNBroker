# Licensing

PWNBroker requires a signed license file. Licenses are **annual** and fully
**offline**: no call-home is needed, so it works on isolated networks.

## Lifecycle

| State | When | Behavior |
|---|---|---|
| Active | more than 30 days left | Full access |
| Expiring | 30 days or fewer left | Full access, renewal banner for admins |
| Grace (read-only) | up to `grace_days` (default 14) after expiry | Browsing and reports work; changes, scans and scheduled jobs stop; endpoint agents keep reporting |
| Locked | past grace, or the license is missing, invalid, bound to another install, or the server clock was rolled back | Every page redirects to **License**; the API and agents get HTTP 402 |

The expiry date is inclusive: a license expiring 2027-11-10 works through that whole day (UTC).

## Customer side

Admins install or renew from **user menu → License**. They can upload the `.lic` file or
paste its text. Installing a renewal early takes effect immediately and loses no
days.

## Vendor side (you)

The signing key lives in `~/.pwnbroker-license/private_key.pem`. **Back it up and
never commit it.** Without it you can't issue renewals that existing installs
accept. The matching public key is embedded in `app/licensing.py`.

```bash
T=tools/licensing/pwnbroker_license.py

python $T issue --customer "Acme Corp"                 # 1-year license
python $T issue --customer "Acme Corp" --days 30       # trial
python $T issue --customer "Acme Corp" --install-id 586F-D352-E7D4-4F42   # bind to one install
python $T renew acme_corp_2027-11-10.lic               # +1 year from current expiry
python $T inspect acme_corp_2027-11-10.lic             # show + verify
```

`--install-id` is optional. The customer sees their Install ID on the License page.
A bound license only works on that install, which stops one purchase being
copied to many servers. The ID changes if `data/` is wiped, so re-issue with
`renew --install-id NEW-ID` when a customer rebuilds their server.

If the key is ever compromised: run `keygen --force`, paste the new public key
into `app/licensing.py`, ship that build, and re-issue every customer's license.

## Files on the install (`data/`, git-ignored)

- `license.key`: the installed license
- `install_id.txt`: this install's ID
- `license_state.json`: the latest time seen, used to detect clock rollback (48h tolerance)
