from __future__ import annotations
import base64,csv,io,os,re,sys
from datetime import datetime,timezone
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import get_json,parse_profile,save_json,session,sha1_key
ROOT=Path(__file__).resolve().parents[1]; CONFIG=ROOT/"sources"/"sources.json"; OUT=ROOT/"data"/"discovered.json"

def html_ovpn(source,s):
 records=[]
 for base in source["base_urls"]:
  r=s.get(base,timeout=30); r.raise_for_status()
  links=re.findall(r'''(?:href|src)=["']([^"']+\.ovpn(?:\?[^"']*)?)["']''',r.text,re.I)
  for link in dict.fromkeys(links):
   url=link if link.startswith("http") else r.url.rsplit("/",1)[0]+"/"+link.lstrip("/")
   try:
    cfg=s.get(url,timeout=30); cfg.raise_for_status()
    p=parse_profile(cfg.text,source["id"],url)
    if p: records.append(p)
   except Exception as exc: print(f"[{source['id']}] config failed: {url}: {exc}")
 return records

def vpngate_csv(source,s):
 r=s.get(source["base_urls"][0],timeout=30); r.raise_for_status()
 marker="#HostName,IP,Score,Ping,Speed,Country,CountryLong,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64"
 if marker not in r.text: raise RuntimeError("VPN Gate CSV format not found")
 rows=csv.DictReader(io.StringIO(marker+"\n"+r.text.split(marker,1)[1].lstrip("\r\n")))
 records=[]
 for row in rows:
  b64=(row.get("OpenVPN_ConfigData_Base64") or "").strip()
  if not b64: continue
  try:
   cfg=base64.b64decode(b64).decode("utf-8","replace")
   p=parse_profile(cfg,source["id"],source["base_urls"][0],row.get("HostName") or "")
   if p: p["country"]=row.get("Country") or None; records.append(p)
  except Exception: continue
 return records

def publicvpnlist_api(source,s):
 key=os.getenv(source.get("secret_env",""))
 if not key: print("[publicvpnlist] API key not configured; source skipped"); return []
 records=[]; page=1
 while page<=20:
  r=s.get(source["base_urls"][0],params={"protocol":"openvpn","status":"online","page":page,"per_page":200},headers={"Authorization":f"Bearer {key}"},timeout=30)
  if r.status_code==401: raise RuntimeError("PublicVPNList API key missing or expired")
  r.raise_for_status(); data=r.json(); rows=data.get("servers",data.get("data",[]))
  if not rows: break
  for row in rows:
   host=row.get("host") or row.get("ip"); port=row.get("port")
   if not host or not port: continue
   proto=str(row.get("transport") or row.get("proto") or "udp").lower()
   records.append({"id":sha1_key(host,port,proto),"source":source["id"],"source_url":source["base_urls"][0],"name":row.get("name") or host,"host":host,"port":int(port),"proto":proto,"auth":row.get("auth_type") or "unknown","country":row.get("country_code"),"external_id":row.get("public_id")})
  page+=1
 return records

def main():
 cfg=get_json(CONFIG,{"sources":[]}); s=session(); all_records=[]
 for source in cfg["sources"]:
  if not source.get("enabled"): continue
  try:
   adapter=source["adapter"]
   records=html_ovpn(source,s) if adapter=="html_ovpn" else vpngate_csv(source,s) if adapter=="vpngate_csv" else publicvpnlist_api(source,s) if adapter=="publicvpnlist_api" else []
   print(f"[{source['id']}] discovered {len(records)}"); all_records.extend(records)
  except Exception as exc: print(f"[{source['id']}] ERROR: {exc}")
 unique={r["id"]:r for r in all_records}
 save_json(OUT,{"generated_at":datetime.now(timezone.utc).isoformat(),"servers":list(unique.values())})
 print(f"total unique: {len(unique)}")
if __name__=="__main__": main()
