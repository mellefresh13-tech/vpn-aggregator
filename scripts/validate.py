from __future__ import annotations
import os,subprocess,sys,tempfile
from datetime import datetime,timezone
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import DATA,get_json,save_json,tcp_probe
INPUT=DATA/"discovered.json"; OUTPUT=DATA/"validated.json"

def openvpn_handshake(profile):
 cfg=profile.get("config")
 if not cfg: return {"status":"not_tested","error":"raw config unavailable"}
 with tempfile.TemporaryDirectory() as td:
  path=Path(td)/"profile.ovpn"; path.write_text(cfg,encoding="utf-8")
  cmd=["sudo","openvpn","--config",str(path),"--connect-timeout","12","--connect-retry-max","1","--ping-exit","10","--verb","3"]
  try: p=subprocess.run(cmd,capture_output=True,text=True,timeout=20)
  except Exception as exc: return {"status":"error","error":str(exc)}
  combined=(p.stdout+"\n"+p.stderr).lower()
  if "initialization sequence completed" in combined: return {"status":"working","error":None}
  if "auth_failed" in combined or "authentication failed" in combined: return {"status":"auth_failed","error":"authentication failed"}
  if "tls error" in combined: return {"status":"tls_failed","error":"tls handshake failed"}
  return {"status":"failed","error":combined[-800:]}

def main():
 data=get_json(INPUT,{"servers":[]}); history=get_json(DATA/"history.json",{"servers":{}}); out=[]
 for p in data["servers"]:
  tcp=tcp_probe(p["host"],p["port"]); record={k:v for k,v in p.items() if k!="config"}
  record["checked_at"]=datetime.now(timezone.utc).isoformat(); record["tcp"]=tcp
  if tcp["reachable"]:
   if p.get("auth")=="username_password" and not (os.getenv("VPNONLINE_USERNAME") and os.getenv("VPNONLINE_PASSWORD")):
    record["status"]="credentials_required"; record["handshake"]={"status":"not_tested","error":"credentials not configured"}
   else:
    record["handshake"]=openvpn_handshake(p); record["status"]=record["handshake"]["status"]
  else: record["status"]="unreachable"
  old=history["servers"].get(record["id"],{}); failures=int(old.get("consecutive_failures",0))
  failures=failures+1 if record["status"]!="working" else 0
  record["consecutive_failures"]=failures
  record["lifecycle"]="dead" if failures>=12 else "quarantine" if failures>=4 else "temporarily_failed" if failures>=1 else "working"
  history["servers"][record["id"]]=record; out.append(record)
 save_json(OUTPUT,{"servers":out}); save_json(DATA/"history.json",history); print(f"validated {len(out)} servers")
if __name__=="__main__": main()
