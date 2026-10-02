from __future__ import annotations
from datetime import datetime,timezone
from common import DATA,get_json,save_json

INPUT=DATA/"validated.json"
OUTPUT=DATA/"servers.json"

def main():
 data=get_json(INPUT,{"servers":[]})
 servers=[]
 for row in data["servers"]:
  item={k:v for k,v in row.items() if k not in ("config","handshake")}
  item["available"]=row.get("status")=="working"
  servers.append(item)
 servers.sort(key=lambda x:(not x["available"],x.get("country") or "",x.get("name") or ""))
 save_json(OUTPUT,{"generated_at":datetime.now(timezone.utc).isoformat(),"servers":servers})
 print(f"catalog: {len(servers)} records, {sum(x['available'] for x in servers)} working")

if __name__=="__main__":
 main()
