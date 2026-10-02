from __future__ import annotations
import hashlib,json,re,socket
from pathlib import Path
import requests
ROOT=Path(__file__).resolve().parents[1]; DATA=ROOT/"data"
def session():
 s=requests.Session(); s.headers.update({"User-Agent":"vpn-aggregator/1.1 (+private catalog monitor)","Accept":"*/*"}); return s
def get_json(path,default):
 return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default
def save_json(path,value):
 path.parent.mkdir(parents=True,exist_ok=True); path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
def sha1_key(host,port,proto): return hashlib.sha1(f"{host}:{port}:{proto}".encode()).hexdigest()
def parse_remote(text):
 m=re.search(r"(?mi)^\s*remote\s+([^\s#]+)(?:\s+(\d+))?",text); return (m.group(1),int(m.group(2) or 1194)) if m else (None,None)
def parse_proto(text):
 m=re.search(r"(?mi)^\s*proto\s+(\S+)",text); return m.group(1).lower() if m else "udp"
def auth_class(text):
 if re.search(r"(?mi)^\s*auth-user-pass\b",text): return "username_password"
 if re.search(r"(?mi)^\s*(cert|key)\s+",text) or "<cert>" in text or "<key>" in text: return "certificate"
 return "anonymous"
def country_from_path(path):
 known={"poland":"PL","germany":"DE","france":"FR","netherlands":"NL","uk":"GB","unitedkingdom":"GB","romania":"RO","italy":"IT","spain":"ES","sweden":"SE","denmark":"DK","finland":"FI","norway":"NO","ukraine":"UA","belarus":"BY","lithuania":"LT","latvia":"LV","estonia":"EE","japan":"JP","usa":"US","canada":"CA","turkey":"TR","russia":"RU"}
 for p in [x for x in path.split("/") if x]:
  key=re.sub(r"[^a-z]","",p.lower())
  if key in known: return known[key]
 return None
def parse_profile(text,source_id,source_url,name=""):
 host,port=parse_remote(text)
 if not host: return None
 proto=parse_proto(text)
 return {"id":sha1_key(host,port,proto),"source":source_id,"source_url":source_url,"name":name or host,"host":host,"port":port,"proto":proto,"auth":auth_class(text),"config":text}
def tcp_probe(host,port,timeout=5):
 try:
  with socket.create_connection((host,port),timeout=timeout): return {"reachable":True,"error":None}
 except Exception as exc: return {"reachable":False,"error":str(exc)}
def config_is_safe(cfg):
 blocked=("up ","down ","route-up ","route-pre-down ","ipchange ","route-change ","learn-address ","client-connect ","client-disconnect ","plugin ","tls-verify ","management ","config ","askpass ","auth-user-pass-verify ")
 for raw in cfg.lower().splitlines():
  line=raw.strip()
  if any(line.startswith(d) for d in blocked): return False
 return True
