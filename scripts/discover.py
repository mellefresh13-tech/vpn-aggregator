from __future__ import annotations
import base64,csv,io,re,sys
from datetime import datetime,timezone
from pathlib import Path
from urllib.parse import urljoin
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import get_json,parse_profile,save_json,session,sha1_key,country_from_path
ROOT=Path(__file__).resolve().parents[1]; CONFIG=ROOT/"sources"/"sources.json"; OUT=ROOT/"data"/"discovered.json"

def vpngate_csv(source,s):
 r=s.get(source["base_urls"][0],timeout=30); r.raise_for_status()
 marker="#HostName,IP,Score,Ping,Speed,Country,CountryLong,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64"
 if marker not in r.text: raise RuntimeError("VPN Gate CSV format not found")
 rows=csv.DictReader(io.StringIO(marker+"\n"+r.text.split(marker,1)[1].lstrip("\r\n"))); records=[]
 for row in rows:
  b64=(row.get("OpenVPN_ConfigData_Base64") or "").strip()
  if not b64: continue
  try:
   cfg=base64.b64decode(b64).decode("utf-8","replace"); p=parse_profile(cfg,source["id"],source["base_urls"][0],row.get("HostName") or "")
   if p:
    p["country"]=row.get("Country") or None; p["latency_ms"]=int(row.get("Ping") or 0) or None; p["speed_kbps"]=int(row.get("Speed") or 0) or None; records.append(p)
  except Exception: continue
 return records

def huntvpn_html(source,s):
 records=[]
 r=s.get(source["base_urls"][0],timeout=30); r.raise_for_status()
 seen_pages=set(); page_url=r.url
 for _ in range(3):
  if page_url in seen_pages: break
  seen_pages.add(page_url)
  page=s.get(page_url,timeout=30); page.raise_for_status()
  server_links=re.findall(r'''href=["']([^"']*/servers/[^"']+)["']''',page.text,re.I)
  for link in dict.fromkeys(server_links):
   url=urljoin(page.url,link)
   try:
    target=s.get(url,timeout=20); target.raise_for_status()
    candidates=[]
    candidates += re.findall(r'''(?:href|data-href|data-url|data-download-url)=["']([^"']*(?:\.ovpn|download|config)[^"']*)["']''',target.text,re.I)
    candidates += re.findall(r'''["'](/[^"']*\.ovpn[^"']*)["']''',target.text,re.I)
    for config_link in dict.fromkeys(candidates):
     cfg=s.get(urljoin(target.url,config_link),timeout=20); cfg.raise_for_status()
     if ".ovpn" in cfg.url.lower() or cfg.text.lstrip().startswith(("client","dev ","remote ","# OpenVPN")):
      p=parse_profile(cfg.text,source["id"],cfg.url)
      if p: p["country"]=country_from_path(target.url); records.append(p)
   except Exception as exc: print(f"[{source['id']}] server failed: {url}: {exc}")
  nxt=re.search(r'''href=["']([^"']*[?&]cursor=[^"']+)["']''',page.text,re.I)
  if not nxt: break
  page_url=urljoin(page.url,nxt.group(1))
 return records

def publicvpnlist_html(source,s):
 records=[]
 countries=["poland","germany","netherlands","france","united-kingdom","romania","italy","spain","sweden","denmark","finland","norway","ukraine","lithuania","latvia","estonia","croatia"]
 for country in countries:
  page_url=urljoin(source["base_urls"][0],country+"/")
  try:
   page=s.get(page_url,timeout=30); page.raise_for_status()
   for link in dict.fromkeys(re.findall(r'''href=["']([^"']+\.ovpn(?:\?[^"']*)?)["']''',page.text,re.I)):
    url=urljoin(page.url,link)
    try:
     cfg=s.get(url,timeout=20); cfg.raise_for_status(); p=parse_profile(cfg.text,source["id"],url)
     if p: p["country"]=country_from_path(page.url); records.append(p)
    except Exception as exc: print(f"[{source['id']}] config failed: {url}: {exc}")
  except Exception as exc: print(f"[{source['id']}] country failed: {country}: {exc}")
 return records

def github_tree(source,s):
 r=s.get(source["base_urls"][0],timeout=30); r.raise_for_status(); records=[]
 for item in r.json().get("tree",[]):
  path=item.get("path","")
  if item.get("type")!="blob" or not path.lower().endswith(".ovpn"): continue
  url=f"https://raw.githubusercontent.com/Zoult/.ovpn/main/{path}"
  try:
   cfg=s.get(url,timeout=20); cfg.raise_for_status(); p=parse_profile(cfg.text,source["id"],url,Path(path).stem)
   if p: p["country"]=country_from_path(path); records.append(p)
  except Exception as exc: print(f"[{source['id']}] raw config failed: {path}: {exc}")
 return records

def main():
 cfg=get_json(CONFIG,{"sources":[]}); s=session(); all_records=[]
 for source in cfg["sources"]:
  if not source.get("enabled"): continue
  try:
   a=source["adapter"]
   if a=="vpngate_csv": records=vpngate_csv(source,s)
   elif a=="huntvpn_html": records=huntvpn_html(source,s)
   elif a=="publicvpnlist_html": records=publicvpnlist_html(source,s)
   elif a=="github_tree": records=github_tree(source,s)
   else: records=[]
   records=[x for x in records if x.get("auth") in ("anonymous","certificate")]
   for item in records: item["source_priority"]=source.get("priority",0)
   print(f"[{source['id']}] discovered eligible {len(records)}"); all_records.extend(records)
  except Exception as exc: print(f"[{source['id']}] ERROR: {exc}")
 unique={}
 for r in all_records:
  old=unique.get(r["id"])
  if old is None or r.get("source_priority",0)>old.get("source_priority",0): unique[r["id"]]=r
 save_json(OUT,{"generated_at":datetime.now(timezone.utc).isoformat(),"servers":list(unique.values())})
 print(f"total unique: {len(unique)}")
if __name__=="__main__": main()
