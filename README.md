# VPN Aggregator

Private OpenVPN catalog and monitoring pipeline.

Pipeline: discover -> parse -> safety classification -> TCP reachability -> OpenVPN handshake -> exit-IP check -> scoring -> deduplication -> lifecycle history -> catalog.

The catalog is generated automatically every 6 hours.

## Source policy

Only sources that can provide OpenVPN profiles without user registration or provider login are accepted.

Active sources:
- Hunt VPN — public .ovpn profiles, no signup.
- PublicVPNList — public .ovpn profiles, no registration.
- VPN Gate — public server feed.
- Zoult/.ovpn — public GitHub archive of .ovpn profiles.

Sources that require an account, login, or manually supplied credentials are excluded.

Discovery also applies a hard authentication filter: profiles requiring username/password authentication are not added to the catalog.

A server is marked available only after TCP reachability and a real OpenVPN control-channel handshake. Source availability is not a trust endorsement.

## Security

- Untrusted .ovpn files are checked before execution.
- Executable hooks, external config includes, management, plugins and auth-verification hooks are rejected.
- Credentials are never written to generated catalog files.
- Intermediate discovered/validated files are not published by Actions.

## Published files

- data/servers.json — current catalog.
- data/history.json — lifecycle history.

## Lifecycle

- working
- temporarily_failed
- quarantine after 4 consecutive failures
- dead after 12 consecutive failures
- recovery returns a server to working.

## Automation

GitHub Actions runs the catalog update every 6 hours.

Local run:

python3 scripts/update_catalog.py


<!-- discovery-fix-run -->
