# Releases & automatic updates (vendor runbook)

Installs update themselves from **your update server at
`https://pwnbroker.space:7585/updates`**. Only
releases signed with your release key are ever installed, and only installs
with an active license receive them.

```
you: build_release.py build → publish ──rsync──▶ update server :7585
                                                   │  POST /v1/check (license)
customer: pwnbroker-updater.timer (hourly) ◀───────┘  GET  /v1/download (1h token)
          verify signature → stop → backup → apply → pip → start → health check
                                                   └─ failure → automatic rollback
```

## Keys (back up both, never commit)

| Key | Location | Signs |
|---|---|---|
| License key | `~/.pwnbroker-license/private_key.pem` | customer licenses |
| Release key | `~/.pwnbroker-release/release_private_key.pem` | releases |

The update server holds **neither** private key. It only has the license
*public* key, which it uses to check who is entitled to updates. A compromised
update server therefore can't push code: installs reject anything not signed
with the release key.

## Shipping a release

```bash
git commit ...                                      # releases are built from committed HEAD only
python tools/release/build_release.py build --bump minor --notes-file CHANGES.md
python tools/release/build_release.py publish 1.1.0 root@pwnbroker.space:/srv/pwnbroker-updates/releases/
```

- `--bump major|minor|patch` updates `app/version.py`, commits, and tags `vX.Y.Z`.
- `--channel beta` releases to beta installs only. To promote it, rebuild the
  same commit as stable under the next version.
- Install timers check hourly with up to 15 minutes of random delay. Each
  install updates inside its own maintenance window (default 02:00–05:00) and
  waits for running scans to finish.
- **Bad release?** Add the version to `/srv/pwnbroker-updates/yanked.txt` and
  installs stop being offered it. Installs where it fails to start roll back by
  themselves. Fix forward with a higher version.
- **Offline customers:** send them
  `releases_out/<version>/pwnbroker-<version>.pwnupdate`. They upload it under
  user menu → Updates.
- **New customer install:** send the release tarball. They run
  `mkdir pwnbroker && tar xzf pwnbroker-X.Y.Z.tar.gz -C pwnbroker && sudo bash pwnbroker/setup.sh`.

`publish` uploads `manifest.sig` last. The server ignores a release directory
until that file exists, so a half-uploaded release is never offered.

## Update server setup (once)

Point the `pwnbroker.space` A record at the server first. Then, from your dev
machine:

```bash
scp -r update_server ~/.pwnbroker-license/public_key.pem root@pwnbroker.space:/root/
ssh -t root@pwnbroker.space bash /root/update_server/install_update_server.sh
```

Keep the `-t`: the script asks for your **Spaceship SSL Manager token** (from
the Spaceship dashboard).

```
customers ──https :7585──▶ nginx ──http 127.0.0.1:7586──▶ update server (gunicorn)
Spaceship ──http  :80 ───▶ nginx (domain validation)
```

The script:
- installs the packages, nginx and the `pwnupdates` user, and puts the server in
  `/opt/pwnbroker-update-server` with its data in `/srv/pwnbroker-updates`
- runs Spaceship's SSL Manager installer, which registers with your token and
  installs your signed certificate into nginx, then keeps renewing it
- points port 7585 at that certificate with `pwnbroker-updates-certsync`; a
  timer re-runs it every 6 hours, so renewals are picked up automatically
- opens ports 80 and 7585 in ufw/firewalld and checks
  `https://pwnbroker.space:7585/updates/v1/health`

If Spaceship is still validating the domain when the script finishes, port 7585
turns on by itself once the certificate arrives. To force a check, run
`sudo pwnbroker-updates-certsync`. Ports 80 and 7585 must also be open in any
cloud-provider firewall.

To update the server code, copy the folder again and re-run the script.
Re-running keeps releases, check-ins and certificates. Other certificate
options: `--ssl letsencrypt` or `--ssl self-signed` (testing only; customers
would then need `PWNBROKER_UPDATE_CA`). See `--help`.

Server files in `/srv/pwnbroker-updates/`:
- `yanked.txt`: versions to stop offering
- `revoked.txt`: license IDs to refuse (for refunds or leaked licenses)
- `checkins.db`: each install's customer, version and last check-in, e.g.
  `sqlite3 checkins.db "select customer, version, last_seen from checkins"`

## Customer-side commands

```bash
sudo /opt/PWNBroker/venv/bin/python3 /opt/PWNBroker/updater/pwnbroker_updater.py check
sudo /opt/PWNBroker/venv/bin/python3 /opt/PWNBroker/updater/pwnbroker_updater.py install
sudo /opt/PWNBroker/venv/bin/python3 /opt/PWNBroker/updater/pwnbroker_updater.py rollback
journalctl -u pwnbroker-updater
```

The last 3 backups (code plus `data/`, including the SQLite DB) are kept in
`/var/backups/pwnbroker/`.

## Your existing git-based server

`/opt/PWNBroker` is a git checkout, so `setup.sh` keeps updating it with
`git pull`, and the updater also works there. Once the repo is private, either
keep pulling with your own credentials, or let the updater manage it like a
customer install.
