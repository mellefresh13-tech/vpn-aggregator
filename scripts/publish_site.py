from __future__ import annotations

import html
import re
import shutil
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from common import DATA, config_is_safe, country_priority, get_json, is_connect_ready

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
PROFILES = DOCS / "profiles"

COUNTRY_NAMES = {
    "PL": "Poland", "DE": "Germany", "FR": "France", "NL": "Netherlands",
    "GB": "United Kingdom", "RO": "Romania", "IT": "Italy", "ES": "Spain",
    "SE": "Sweden", "DK": "Denmark", "FI": "Finland", "NO": "Norway",
    "UA": "Ukraine", "LT": "Lithuania", "LV": "Latvia", "EE": "Estonia",
    "CZ": "Czechia", "AT": "Austria", "BE": "Belgium", "PT": "Portugal",
    "HU": "Hungary", "SK": "Slovakia", "SI": "Slovenia", "HR": "Croatia",
    "BG": "Bulgaria", "IE": "Ireland", "GR": "Greece", "CH": "Switzerland",
    "JP": "Japan", "KR": "South Korea", "US": "United States", "CA": "Canada",
    "AU": "Australia", "TH": "Thailand", "VN": "Vietnam", "RU": "Russia",
    "TR": "Turkey", "CN": "China", "IN": "India", "BR": "Brazil",
    "ZZ": "Unknown",
}


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


def format_generated_at(value: str | None) -> str:
    if not value:
        return "unknown time"
    try:
        raw = value.strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return f"{dt.day} {dt.strftime('%b %Y, %H:%M')} UTC"
    except Exception:
        return value


def country_label(code: str) -> str:
    name = COUNTRY_NAMES.get(code, code)
    return f"{name} ({code})" if code and code != name else (code or "Unknown")


def main(index_only: bool = False):
    catalog = get_json(DATA / "servers.json", {"servers": []})
    discovered = get_json(DATA / "discovered.json", {"servers": []})
    configs = {x["id"]: x.get("config", "") for x in discovered.get("servers", [])}

    working = [x for x in catalog.get("servers", []) if x.get("available")]
    groups = defaultdict(list)
    published = []

    has_configs = any(bool(c) for c in configs.values())
    if has_configs and not index_only:
        if DOCS.exists():
            shutil.rmtree(DOCS)
        PROFILES.mkdir(parents=True, exist_ok=True)

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
    else:
        PROFILES.mkdir(parents=True, exist_ok=True)
        existing = {
            str(p.relative_to(DOCS)).replace("\\", "/")
            for p in PROFILES.rglob("*.ovpn")
        }
        for server in working:
            auth = server.get("auth", "")
            if not is_connect_ready(auth):
                continue
            country = server.get("country") or "ZZ"
            filename = safe_name(server.get("name") or server["id"]) + ".ovpn"
            rel = f"profiles/{safe_name(country)}/{filename}"
            if rel not in existing:
                country_dir = PROFILES / safe_name(country)
                if not country_dir.is_dir():
                    continue
                matches = list(country_dir.glob(safe_name(server.get("name") or server["id"]) + ".ovpn"))
                if not matches:
                    continue
                rel = str(matches[0].relative_to(DOCS)).replace("\\", "/")
            item = dict(server)
            item["profile_path"] = rel
            groups[country].append(item)
            published.append(item)

    def esc(v):
        return html.escape(str(v if v is not None else ""))

    country_order = sorted(
        groups.keys(),
        key=lambda c: (-country_priority(c), c),
    )

    tiles = []
    panels = []
    for idx, country in enumerate(country_order):
        items = sorted(
            groups[country],
            key=lambda x: (
                -float(x.get("score") or 0),
                -(x.get("speed_kbps") or 0),
                x.get("handshake_ms") or 999999,
                x.get("name") or "",
            ),
        )
        cid = esc(country)
        label = esc(country_label(country))
        open_attr = " open" if idx < 2 else ""
        tiles.append(
            f'<button type="button" class="tile" data-target="c-{cid}" '
            f'aria-expanded="{"true" if idx < 2 else "false"}">'
            f'<span class="tile-code">{cid}</span>'
            f'<span class="tile-name">{label}</span>'
            f'<span class="tile-count">{len(items)}</span>'
            f"</button>"
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
                f"</div>"
                f'<a class="download" href="{esc(s["profile_path"])}" download>Download .ovpn</a>'
                "</article>"
            )
        panels.append(
            f'<details class="country" id="c-{cid}" data-country="{cid}"{open_attr}>'
            f'<summary><span class="sum-title">{label}</span>'
            f'<span class="sum-count">{len(items)} servers</span></summary>'
            f'{ "".join(rows) }'
            "</details>"
        )

    generated = format_generated_at(catalog.get("generated_at"))
    pl_count = len(groups.get("PL", []))
    eu_count = sum(len(v) for k, v in groups.items() if country_priority(k) >= 200)
    total = len(catalog.get("servers") or [])
    working_n = len(working)
    published_n = len(published)

    stats_line = (
        f"Updated {generated}"
        f" · {total} in catalog"
        f" · {working_n} working"
        f" · {published_n} published"
        f" · Poland: {pl_count}"
        f" · Europe: {eu_count}"
    )

    index = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPN Aggregator</title><style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}
body{{margin:0;background:#0b1020;color:#e8ecf4;font:15px system-ui,-apple-system,Segoe UI,sans-serif}}
main{{max-width:1100px;margin:auto;padding:24px 16px 48px}}
h1{{margin:0 0 6px;font-size:28px}}
.stats{{color:#9da9bf;margin-bottom:6px;line-height:1.45;font-size:14px}}
.note{{color:#7f8aa3;font-size:13px;margin-bottom:14px}}
input#q{{width:100%;padding:12px 14px;border-radius:10px;border:1px solid #2a3550;background:#121a2d;color:#fff;margin:0 0 16px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin-bottom:18px}}
.tile{{display:flex;flex-direction:column;gap:4px;align-items:flex-start;text-align:left;
  background:#121a2d;border:1px solid #26324b;border-radius:12px;padding:12px;color:#e8ecf4;cursor:pointer;
  font:inherit;transition:border-color .15s,background .15s}}
.tile:hover,.tile.active{{border-color:#3b82f6;background:#152038}}
.tile-code{{font-weight:700;font-size:18px;letter-spacing:.02em}}
.tile-name{{font-size:12px;color:#9da9bf;line-height:1.25}}
.tile-count{{font-size:12px;color:#60a5fa;margin-top:2px}}
.country{{background:#0e1528;border:1px solid #26324b;border-radius:12px;margin:10px 0;padding:0 12px 8px}}
.country>summary{{cursor:pointer;list-style:none;display:flex;justify-content:space-between;align-items:center;
  gap:12px;padding:14px 4px;font-weight:650;user-select:none}}
.country>summary::-webkit-details-marker{{display:none}}
.country>summary::before{{content:"▸";color:#60a5fa;margin-right:8px;transition:transform .15s}}
.country[open]>summary::before{{transform:rotate(90deg)}}
.sum-title{{flex:1}}
.sum-count{{color:#9da9bf;font-weight:500;font-size:13px}}
.card{{background:#121a2d;border:1px solid #26324b;border-radius:12px;padding:14px;margin:8px 0;
  display:grid;grid-template-columns:1fr auto;gap:8px 16px}}
.title{{font-weight:650;word-break:break-word}}
.meta{{grid-column:1;color:#9da9bf;display:flex;flex-wrap:wrap;gap:10px;font-size:13px}}
.download{{grid-column:2;grid-row:1/3;align-self:center;background:#2563eb;color:#fff;text-decoration:none;
  padding:9px 13px;border-radius:9px;white-space:nowrap}}
@media(max-width:650px){{.card{{grid-template-columns:1fr}}.download{{grid-column:1;grid-row:auto;justify-self:start}}}}
.empty{{color:#9da9bf;padding:18px 0}}
.hint{{color:#7f8aa3;font-size:12px;margin:-6px 0 12px}}
</style></head><body><main>
<h1>VPN Aggregator</h1>
<div class="stats">{esc(stats_line)}</div>
<div class="note">Only connect-ready profiles: no interactive login. Certificate / anonymous / embedded public credentials. Free public endpoints — not a privacy guarantee.</div>
<input id="q" placeholder="Search country, server, protocol..." oninput="filter()">
<p class="hint">Countries as a grid — click a tile or expand a section below.</p>
<div class="grid" id="country-grid">{ "".join(tiles) if tiles else ""}</div>
<div id="panels">
{ "".join(panels) if panels else '<div class="empty">No currently working servers. Wait for the next monitor run.</div>'}
</div>
<script>
function filter(){{
  const q=document.getElementById('q').value.toLowerCase();
  document.querySelectorAll('.card').forEach(e=>{{
    e.style.display=e.textContent.toLowerCase().includes(q)?'':'none';
  }});
  document.querySelectorAll('.country').forEach(sec=>{{
    const visible=[...sec.querySelectorAll('.card')].some(c=>c.style.display!=='none');
    const matchSummary=sec.textContent.toLowerCase().includes(q);
    sec.style.display=(visible||matchSummary)?'':'none';
    if(q && visible) sec.open=true;
  }});
  document.querySelectorAll('.tile').forEach(t=>{{
    const id=t.getAttribute('data-target');
    const sec=document.getElementById(id);
    t.style.display=(!sec||sec.style.display==='none')?'none':'';
  }});
}}
document.getElementById('country-grid').addEventListener('click',e=>{{
  const t=e.target.closest('.tile');
  if(!t) return;
  const sec=document.getElementById(t.getAttribute('data-target'));
  if(!sec) return;
  sec.open=true;
  sec.scrollIntoView({{behavior:'smooth',block:'start'}});
  document.querySelectorAll('.tile').forEach(x=>x.classList.remove('active'));
  t.classList.add('active');
}});
</script>
</main></body></html>
"""
    (DOCS / "index.html").write_text(index, encoding="utf-8")
    (DOCS / ".nojekyll").write_text("", encoding="utf-8")
    print(f"pages: working={working_n}, published={published_n}, PL={pl_count}, EU={eu_count}")


if __name__ == "__main__":
    import sys
    main(index_only=("--index-only" in sys.argv))
