from __future__ import annotations
import html,re,shutil
from collections import defaultdict
from pathlib import Path
from common import DATA,get_json,config_is_safe

ROOT=Path(__file__).resolve().parents[1]
DOCS=ROOT/"docs"
PROFILES=DOCS/"profiles"

def safe_name(value):
 return re.sub(r"[^A-Za-z0-9._-]+","_",value or "server").strip("._")[:80] or "server"

def main():
 catalog=get_json(DATA/"servers.json",{"servers":[]})
 discovered=get_json(DATA/"discovered.json",{"servers":[]})
 configs={x["id"]:x.get("config","") for x in discovered["servers"]}
 if DOCS.exists(): shutil.rmtree(DOCS)
 PROFILES.mkdir(parents=True,exist_ok=True)

 working=[x for x in catalog["servers"] if x.get("available")]
 groups=defaultdict(list)
 published=[]
 for server in working:
  cfg=configs.get(server["id"],"")
  if not cfg or server.get("auth") not in ("anonymous","certificate") or not config_is_safe(cfg):
   continue
  country=server.get("country") or "ZZ"
  country_dir=PROFILES/safe_name(country)
  country_dir.mkdir(parents=True,exist_ok=True)
  filename=safe_name(server.get("name") or server["id"])+".ovpn"
  path=country_dir/filename
  path.write_text(cfg,encoding="utf-8")
  item=dict(server); item["profile_path"]=f"profiles/{safe_name(country)}/{filename}"
  groups[country].append(item); published.append(item)

 def esc(v):
  return html.escape(str(v if v is not None else ""))

 cards=[]
 for country in sorted(groups):
  items=sorted(groups[country],key=lambda x:(-float(x.get("score") or 0),x.get("handshake_ms") or 999999,x.get("name") or ""))
  rows=[]
  for s in items:
   rows.append(
    '<article class="card">'
    f'<div class="title">{esc(s.get("name") or s["id"])}</div>'
    f'<div class="meta"><span>Score {esc(s.get("score"))}</span><span>Handshake {esc(s.get("handshake_ms"))} ms</span>'
    f'<span>Latency {esc(s.get("latency_ms") or "—")} ms</span><span>{esc(s.get("proto","").upper())}</span></div>'
    f'<a class="download" href="{esc(s["profile_path"])}" download>Download .ovpn</a>'
    '</article>'
   )
  cards.append(f'<section class="country"><h2>{esc(country)} <small>{len(items)}</small></h2>{"".join(rows)}</section>')

 generated=esc(catalog.get("generated_at",""))
 index=f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPN Aggregator</title><style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;background:#0b1020;color:#e8ecf4;font:15px system-ui,-apple-system,Segoe UI,sans-serif}}
main{{max-width:1100px;margin:auto;padding:28px 18px}}h1{{margin:0 0 8px;font-size:32px}}h2{{margin:28px 0 10px}}small{{opacity:.55;font-size:.65em}}
.stats{{color:#9da9bf;margin-bottom:18px}}input{{width:100%;padding:12px 14px;border-radius:10px;border:1px solid #2a3550;background:#121a2d;color:#fff;margin:12px 0 20px}}
.card{{background:#121a2d;border:1px solid #26324b;border-radius:12px;padding:14px;margin:8px 0;display:grid;grid-template-columns:1fr auto;gap:8px 16px}}
.title{{font-weight:650;word-break:break-word}}.meta{{grid-column:1;color:#9da9bf;display:flex;flex-wrap:wrap;gap:10px;font-size:13px}}
.download{{grid-column:2;grid-row:1/3;align-self:center;background:#2563eb;color:#fff;text-decoration:none;padding:9px 13px;border-radius:9px;white-space:nowrap}}
@media(max-width:650px){{.card{{grid-template-columns:1fr}}.download{{grid-column:1;grid-row:auto;justify-self:start}}}}
.empty{{color:#9da9bf;padding:18px 0}}
</style></head><body><main>
<h1>VPN Aggregator</h1>
<div class="stats">Generated {generated} · Found {len(catalog["servers"])} profiles · Working {len(working)} · Published {len(published)}</div>
<input id="q" placeholder="Search country, server, protocol..." oninput="filter()">
{"".join(cards) if cards else '<div class="empty">No currently working servers.</div>'}
<script>function filter(){{const q=document.getElementById('q').value.toLowerCase();document.querySelectorAll('.card,.country').forEach(e=>e.style.display=e.textContent.toLowerCase().includes(q)?'':'none')}};</script>
</main></body></html>
"""
 (DOCS/"index.html").write_text(index,encoding="utf-8")
 (DOCS/".nojekyll").write_text("",encoding="utf-8")
 print(f"pages: working={len(working)}, published={len(published)}")

if __name__=="__main__": main()
