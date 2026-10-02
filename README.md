# VPN Aggregator

Private OpenVPN catalog and monitoring pipeline.

Pipeline: discover -> parse -> safety classification -> TCP reachability -> OpenVPN handshake -> exit-IP check -> scoring -> deduplication -> lifecycle history -> catalog.

The catalog is generated automatically every 6 hours.

Sources:
- VPNonline Poland — Polish source; account credentials come only from GitHub Secrets.
- VPNBook — public OpenVPN service with provider-published shared credentials.
- VPN Gate — public server feed.
- Hunt VPN — public volunteer-server catalog.
- Zoult/.ovpn — secondary public GitHub mirror.
- PublicVPNList — adapter retained but disabled until an API key is configured.

A server is marked available only after TCP reachability and a real OpenVPN control-channel handshake. Source availability is not a trust endorsement.

Security:
- Untrusted .ovpn files are checked before execution.
- Executable hooks, external config includes, management, plugins and auth-verification hooks are rejected.
- Credentials are never written to generated catalog files.
- Intermediate discovered/validated files are not published by Actions.

Published files:
- data/servers.json — current catalog.
- data/history.json — lifecycle history.

Lifecycle:
- working
- temporarily_failed
- quarantine after 4 consecutive failures
- dead after 12 consecutive failures
- recovery returns a server to working.

Local run: python3 scripts/update_catalog.py
