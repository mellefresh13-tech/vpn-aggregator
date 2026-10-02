# VPN Aggregator

Private OpenVPN catalog and monitoring pipeline.

Pipeline: discover → parse → make connect-ready → safety classification → TCP reachability → OpenVPN handshake → exit-IP check → scoring → deduplication → lifecycle history → GitHub Pages.

The catalog is generated automatically every 6 hours.

## Goal

Publish **ready-to-connect** `.ovpn` files you can download anytime:

- no interactive username/password prompt
- either certificate / anonymous auth, or public credentials already embedded in the profile
- only servers that passed a real OpenVPN handshake in CI

## Source policy

Only sources that can provide OpenVPN profiles without user registration are accepted.

Active sources:

- **VPN Gate** — official public CSV feed; configs are made connect-ready with documented public credentials `vpn` / `vpn` embedded inline when needed
- **VPN Gate mirror** — jsDelivr mirror of the same feed (fallback)
- **PublicVPNList** — public `.ovpn` downloads, EU-focused scrape order (PL first)
- **Hunt VPN** — public `.ovpn` profiles
- **Zoult/.ovpn** — public GitHub archive of `.ovpn` profiles

Profiles that still require unknown interactive credentials are discarded.

## Connect-ready rule

A profile is published only if:

1. `auth` is one of: `anonymous`, `certificate`, `embedded_credentials`
2. config passes safety checks (no executable hooks / plugins / management)
3. TCP port is reachable
4. OpenVPN control-channel handshake succeeds in CI

VPN Gate profiles that originally used `auth-user-pass` are rewritten to include:

```text
<auth-user-pass>
vpn
vpn
</auth-user-pass>
```

so common OpenVPN clients can connect without typing credentials.

## Country priority

Scoring boosts:

1. **Poland (PL)** — highest
2. other **EU** countries
3. everything else

GitHub Pages lists countries in that order, then by score / speed.

## Security

- Untrusted `.ovpn` files are checked before OpenVPN is executed.
- Executable hooks, external config includes, management, plugins and auth-verification hooks are rejected.
- Free public VPN endpoints are **not** a privacy guarantee. Use only for connectivity testing / low-risk browsing.

## Published files

- `data/servers.json` — current catalog metadata
- `data/history.json` — lifecycle history
- `docs/` — GitHub Pages site with downloadable `.ovpn` files grouped by country

## Lifecycle

- `working`
- `temporarily_failed`
- `quarantine` after 4 consecutive failures
- `dead` after 12 consecutive failures
- recovery returns a server to `working`

## Automation

GitHub Actions runs the catalog update every 6 hours and deploys Pages when `docs/` changes.

Local run:

```bash
pip install -r requirements.txt
sudo apt-get install -y openvpn   # needed for handshake checks
python3 scripts/update_catalog.py
```
