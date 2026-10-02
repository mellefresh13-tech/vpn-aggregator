# VPN Aggregator

Private OpenVPN catalog and monitoring pipeline.

Pipeline: discover -> parse -> authentication classification -> credentials check -> TCP/OpenVPN check -> exit IP/country -> latency/speed for best candidates -> deduplicate -> lifecycle history -> catalog.

Sources: VPNonline (Poland/Europe), VPN Gate, Hunt VPN, and optional PublicVPNList API.

Optional GitHub Secrets: VPNONLINE_USERNAME, VPNONLINE_PASSWORD, PUBLICVPNLIST_API_KEY.

Secrets are read only from the environment and never written to generated catalog files.

Repository layout:
- sources/ source adapters and configuration
- data/ generated catalog and history
- scripts/ discovery, parsing, validation and catalog update
- .github/workflows/monitor.yml scheduled monitor

Run locally with: python3 scripts/update_catalog.py
