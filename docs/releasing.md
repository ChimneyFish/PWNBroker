# Releases & automatic updates (vendor runbook)

Installs update themselves from **your update server on port 7585**. Only
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
python tools/release/build_release.py publish 1.1.0 root@updates.yourhost:/srv/pwnbroker-updates/releases/
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
  `mkdir pwnbroker && tar xzf pwnbroker-X.Y.Z.tar.gz -C pwnbroker && sudo UPDATE_URL=https://updates.yourhost:7585 bash pwnbroker/setup.sh`.

`publish` uploads `manifest.sig` last. The server ignores a release directory
until that file exists, so a half-uploaded release is never offered.

## Update server setup (once)

```bash
sudo useradd --system --home /srv/pwnbroker-updates pwnupdates
sudo mkdir -p /srv/pwnbroker-updates/{releases,ssl} /opt/pwnbroker-update-server
sudo cp update_server/{server.py,requirements.txt} /opt/pwnbroker-update-server/
sudo python3 -m venv /opt/pwnbroker-update-server/venv
sudo /opt/pwnbroker-update-server/venv/bin/pip install -r /opt/pwnbroker-update-server/requirements.txt
sudo cp ~/.pwnbroker-license/public_key.pem /srv/pwnbroker-updates/license_public_key.pem
# TLS cert for the hostname customers use → /srv/pwnbroker-updates/ssl/{cert,key}.pem
sudo chown -R pwnupdates: /srv/pwnbroker-updates
sudo cp update_server/pwnbroker-update-server.service /etc/systemd/system/
sudo systemctl enable --now pwnbroker-update-server
sudo ufw allow 7585/tcp
curl https://updates.yourhost:7585/v1/health
```

Use a CA-signed certificate (for example Let's Encrypt) so installs can verify
it out of the box. For a self-signed cert, customers set
`PWNBROKER_UPDATE_CA=/path/to/cert.pem` in their `.env`.

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
