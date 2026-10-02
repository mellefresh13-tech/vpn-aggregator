from __future__ import annotations

import html
import re
import shutil
from collections import defaultdict
from pathlib import Path

from common import DATA, config_is_safe, country_priority, get_json, is_connect_ready

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
PROFILES = DOCS / "profiles"


def safe_name(value):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value or "server").strip("._")[:80] or "server"


def format_speed(kbps):
    if not kbps:
        return "—"
    try:
        mbps = float(kbps) / 1_000_000
        if mbps >= 0.1:
            return f"{mbps:.1f} Mbps"
        return f"{float(kbps)/1000:.0f} kbps"
    except Exception:
        return "—"


def main():
    catalog = get_json(DATA / "servers.json", {"servers": []})
    discovered = get_json(DATA / "discovered.json", {"servers": []})
    configs = {x["id"]: x.get("config", "") for x in discovered["servers"]}

    if DOCS.exists():
        shutil.rmtree(DOCS)
    PROFILES.mkdir(parents=True, exist_ok=True)

    working = [x for x in catalog["servers"] if x.get("available")]
    groups = defaultdict(list)
    published = []

    for server in working:
        cfg = configs.get(server["id"], "")
        auth = server.get("auth", "")
        if not cfg or not is_connect_ready(auth) or not config_is_safe(cfg):
            continue

        country = server.get("country") or "ZZ"
        country_dir = PROFILES / safe_name(country)
        country_dir.mkdir(parents=True, exist_ok=True)
        filename = safe_name(server.get("name") or server["id"]) + ".ovpn"
        path = country_dir / filename
        path.write_text(cfg, encoding="utf-8")

        item = dict(server)
        item["profile_path"] = f"profiles/{safe_name(country)}/{filename}"
        groups[country].append(item)
        published.append(item)

    def esc(v):
        return html.escape(str(v if v is not None else ""))

    # PL first, then other EU, then the rest — each group by score/speed.
    country_order = sorted(
        groups.keys(),
        key=lambda c: (-country_priority(c), c),
    )

    cards = []
    for country in country_order:
        items = sorted(
            groups[country],
            key=lambda x: (
                -float(x.get("score") or 0),
                -(x.get("speed_kbps") or 0),
                x.get("handshake_ms") or 999999,
                x.get("name") or "",
            ),
        )
        rows = []
        for s in items:
            rows.append(
                '<article class="card">'
                f'<div class="title">{esc(s.get("name") or s["id"])}</div>'
                f'<div class="meta">'
                f'<span>Score {esc(s.get("score"))}</span>'
                f'<span>Speed {esc(format_speed(s.get("speed_kbps")))}</span>'
                f'<span>Handshake {esc(s.get("handshake_ms"))} ms</span>'
                f'<span>Latency {esc(s.get("latency_ms") or "—")} ms</span>'
                f'<span>{esc((s.get("proto") or "").upper())}</span>'
                f'<span>Auth {esc(s.get("auth"))}</span>'
                f'</div>'
                f'<a class="download" href="{esc(s["profile_path"])}" download>Download .ovpn</a>'
                "</article>"
            )
        cards.append(
            f'<section class="country" data-country="{esc(country)}">' 
            f'<h2>{esc(country)} <small>{len(items)}</small></h2>'
            f'{ "".join(rows) }'
            "</section>"
        )

    generated = esc(catalog.get("generated_at", ""))
    pl_count = len(groups.get("PL", []))
    eu_count = sum(len(v) for k, v in groups.items() if country_priority(k) >= 200)

    index = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPN Aggregator</title><style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}
body{{margin:0;background:#0b1020;color:#e8ecf4;font:15px system-ui,-apple-system,Segoe UI,sans-serif}}
main{{max-width:1100px;margin:auto;padding:28px 18px}}
h1{{margin:0 0 8px;font-size:32px}}h2{{margin:28px 0 10px}}small{{opacity:.55;font-size:.65em}}
.stats{{color:#9da9bf;margin-bottom:8px}}.note{{color:#7f8aa3;font-size:13px;margin-bottom:14px}}
input{{width:100%;padding:12px 14px;border-radius:10px;border:1px solid #2a3550;background:#121a2d;color:#fff;margin:12px 0 20px}}
.card{{background:#121a2d;border:1px solid #26324b;border-radius:12px;padding:14px;margin:8px 0;display:grid;grid-template-columns:1fr auto;gap:8px 16px}}
.title{{font-weight:650;word-break:break-word}}
.meta{{grid-column:1;color:#9da9bf;display:flex;flex-wrap:wrap;gap:10px;font-size:13px}}
.download{{grid-column:2;grid-row:1/3;align-self:center;background:#2563eb;color:#fff;text-decoration:none;padding:9px 13px;border-radius:9px;white-space:nowrap}}
@media(max-width:650px){{.card{{grid-template-columns:1fr}}.download{{grid-column:1;grid-row:auto;justify-self:start}}}}
.empty{{color:#9da9bf;padding:18px 0}}
</style></head><body><main>
<h1>VPN Aggregator</h1>
<div class="stats">Generated {generated} · Catalog {len(catalog["servers"])} · Working {len(working)} · Published {len(published)} · PL {pl_count} · EU {eu_count}</div>
<div class="note">Only connect-ready profiles: no interactive login. Certificate / anonymous / embedded public credentials. Free public endpoints — not a privacy guarantee.</div>
<input id="q" placeholder="Search country, server, protocol..." oninput="filter()">
{"".join(cards) if cards else '<div class="empty">No currently working servers. Wait for the next monitor run.</div>'}
<script>function filter(){{const q=document.getElementById('q').value.toLowerCase();document.querySelectorAll('.card,.country').forEach(e=>e.style.display=e.textContent.toLowerCase().includes(q)?'':'none')}};</script>
</main></body></html>
"""
    (DOCS / "index.html").write_text(index, encoding="utf-8")
    (DOCS / ".nojekyll").write_text("", encoding="utf-8")
    print(f"pages: working={len(working)}, published={len(published)}, PL={pl_count}, EU={eu_count}")


if __name__ == "__main__":
    main()
