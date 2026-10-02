from __future__ import annotations
from datetime import datetime,timezone
from common import DATA,get_json,save_json
INPUT=DATA/"validated.json"; OUTPUT=DATA/"servers.json"
def score(row):
 if row.get("status")!="working": return 0
 hs=row.get("handshake",{}).get("handshake_ms") or 99999; latency=row.get("latency_ms") or 99999
 return round(row.get("source_priority",0)+10+max(0,30-hs/100)+max(0,20-latency/10),2)
def main():
 data=get_json(INPUT,{"servers":[]}); servers=[]
 for row in data["servers"]:
  item={k:v for k,v in row.items() if k not in ("config","handshake")}
  item["available"]=row.get("status")=="working"; item["score"]=score(row)
  item["exit_ip"]=row.get("handshake",{}).get("exit_ip"); item["handshake_ms"]=row.get("handshake",{}).get("handshake_ms")
  servers.append(item)
 servers.sort(key=lambda x:(-x["score"],x.get("country") or "ZZ",x.get("name") or ""))
 save_json(OUTPUT,{"generated_at":datetime.now(timezone.utc).isoformat(),"schema_version":1,"servers":servers})
 print(f"catalog: {len(servers)} records, {sum(x['available'] for x in servers)} working")
if __name__=="__main__": main()
