from __future__ import annotations
import os,subprocess,sys,tempfile,time
from datetime import datetime,timezone
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import DATA,get_json,save_json,tcp_probe,config_is_safe
INPUT=DATA/"discovered.json"; OUTPUT=DATA/"validated.json"

def openvpn_handshake(profile):
 cfg=profile.get("config")
 if not cfg: return {"status":"not_tested","error":"raw config unavailable"}
 if not config_is_safe(cfg): return {"status":"rejected","error":"config contains a blocked executable directive"}
 proc=None
 with tempfile.TemporaryDirectory() as td:
  path=Path(td)/"profile.ovpn"; path.write_text(cfg,encoding="utf-8")
  cmd=["sudo","openvpn","--config",str(path),"--connect-timeout","12","--connect-retry-max","1","--ping-exit","10","--verb","3"]
  username=os.getenv("VPNONLINE_USERNAME"); password=os.getenv("VPNONLINE_PASSWORD")
  auth_file=None
  if username and password:
   auth_file=Path(td)/"auth.txt"; auth_file.write_text(username+"\n"+password+"\n",encoding="utf-8"); auth_file.chmod(0o600); cmd += ["--auth-user-pass",str(auth_file)]
  try:
   proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
   started=time.monotonic(); output=[]; connected=False
   while time.monotonic()-started<18:
    line=proc.stdout.readline()
    if line:
     output.append(line); low=line.lower()
     if "initialization sequence completed" in low: connected=True; break
     if "auth_failed" in low or "authentication failed" in low: break
    elif proc.poll() is not None: break
   if connected:
    time.sleep(1); ip=None
    try:
     import requests
     rr=requests.get("https://api.ipify.org?format=json",timeout=5)
     if rr.ok: ip=rr.json().get("ip")
    except Exception: pass
    return {"status":"working","error":None,"exit_ip":ip,"handshake_ms":int((time.monotonic()-started)*1000)}
   text="".join(output).lower()
   if "auth_failed" in text or "authentication failed" in text: return {"status":"auth_failed","error":"authentication failed"}
   if "tls error" in text or "tls key negotiation failed" in text: return {"status":"tls_failed","error":"tls handshake failed"}
   return {"status":"failed","error":text[-1200:]}
  except Exception as exc: return {"status":"error","error":str(exc)}
  finally:
   if proc:
    try: proc.terminate(); proc.wait(timeout=3)
    except Exception:
     try: proc.kill()
     except Exception: pass

def main():
 data=get_json(INPUT,{"servers":[]}); history=get_json(DATA/"history.json",{"servers":{}}); out=[]; now=datetime.now(timezone.utc).isoformat()
 for p in data["servers"]:
  tcp=tcp_probe(p["host"],p["port"]); record={k:v for k,v in p.items() if k!="config"}; record["checked_at"]=now; record["tcp"]=tcp
  if not tcp["reachable"]:
   record["status"]="unreachable"; record["handshake"]={"status":"not_tested","error":"tcp unreachable"}
  elif p.get("auth")=="username_password" and not (os.getenv("VPNONLINE_USERNAME") and os.getenv("VPNONLINE_PASSWORD")):
   record["status"]="credentials_required"; record["handshake"]={"status":"not_tested","error":"credentials not configured"}
  else:
   record["handshake"]=openvpn_handshake(p); record["status"]=record["handshake"]["status"]
  old=history["servers"].get(record["id"],{}); failures=int(old.get("consecutive_failures",0)); failures=0 if record["status"]=="working" else failures+1
  record["consecutive_failures"]=failures
  record["lifecycle"]="working" if record["status"]=="working" else "dead" if failures>=12 else "quarantine" if failures>=4 else "temporarily_failed"
  record["first_seen"]=old.get("first_seen",now); record["last_seen"]=now
  history["servers"][record["id"]]=record; out.append(record)
 save_json(OUTPUT,{"generated_at":now,"servers":out}); save_json(DATA/"history.json",history)
 print(f"validated {len(out)} servers; working={sum(x['status']=='working' for x in out)}")
if __name__=="__main__": main()
