from __future__ import annotations

import hashlib
import json
import re
import socket
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"

# Public static credentials for VPN Gate–derived free sources.
KNOWN_PUBLIC_AUTH = {
    "vpngate": ("vpn", "vpn"),
    "vpngate_mirror": ("vpn", "vpn"),
    "auto_ovpn": ("vpn", "vpn"),
    "fdciabdul": ("vpn", "vpn"),
    "tdxf1_sync": ("vpn", "vpn"),
    "mizmaze_auto": ("vpn", "vpn"),
    "ovpn_scraper": ("vpn", "vpn"),
    "cynegeirus": ("vpn", "vpn"),
}

EU_COUNTRIES = {
    "PL", "DE", "FR", "NL", "GB", "RO", "IT", "ES", "SE", "DK", "FI", "NO",
    "UA", "LT", "LV", "EE", "CZ", "AT", "BE", "PT", "HU", "SK", "SI", "HR",
    "BG", "IE", "GR", "CH",
}

COUNTRY_ALIASES = {
    "poland": "PL", "pl": "PL",
    "germany": "DE", "de": "DE",
    "france": "FR", "fr": "FR",
    "netherlands": "NL", "nl": "NL",
    "uk": "GB", "unitedkingdom": "GB", "greatbritain": "GB", "gb": "GB",
    "romania": "RO", "ro": "RO",
    "italy": "IT", "it": "IT",
    "spain": "ES", "es": "ES",
    "sweden": "SE", "se": "SE",
    "denmark": "DK", "dk": "DK",
    "finland": "FI", "fi": "FI",
    "norway": "NO", "no": "NO",
    "ukraine": "UA", "ua": "UA",
    "belarus": "BY", "by": "BY",
    "lithuania": "LT", "lt": "LT",
    "latvia": "LV", "lv": "LV",
    "estonia": "EE", "ee": "EE",
    "japan": "JP", "jp": "JP",
    "usa": "US", "unitedstates": "US", "us": "US",
    "canada": "CA", "ca": "CA",
    "turkey": "TR", "tr": "TR",
    "russia": "RU", "ru": "RU",
    "korearepublicof": "KR", "southkorea": "KR", "kr": "KR",
    "czechrepublic": "CZ", "czechia": "CZ", "cz": "CZ",
    "austria": "AT", "at": "AT",
    "belgium": "BE", "be": "BE",
    "portugal": "PT", "pt": "PT",
    "hungary": "HU", "hu": "HU",
    "slovakia": "SK", "sk": "SK",
    "slovenia": "SI", "si": "SI",
    "croatia": "HR", "hr": "HR",
    "bulgaria": "BG", "bg": "BG",
    "ireland": "IE", "ie": "IE",
    "greece": "GR", "gr": "GR",
    "switzerland": "CH", "ch": "CH",
    "australia": "AU", "au": "AU",
    "thailand": "TH", "th": "TH",
    "vietnam": "VN", "vn": "VN",
    "india": "IN", "in": "IN",
}


def session():
    s = requests.Session()
    s.headers.update({
        "User-Agent": "vpn-aggregator/1.4 (+ready-to-connect catalog)",
        "Accept": "*/*",
    })
    return s


def get_json(path, default):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def save_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def sha1_key(host, port, proto):
    return hashlib.sha1(f"{host}:{port}:{proto}".encode()).hexdigest()


def parse_remote(text):
    m = re.search(r"(?mi)^\s*remote\s+([^\s#]+)(?:\s+(\d+))?", text)
    return (m.group(1), int(m.group(2) or 1194)) if m else (None, None)


def parse_proto(text):
    m = re.search(r"(?mi)^\s*proto\s+(\S+)", text)
    return m.group(1).lower() if m else "udp"


def has_inline_auth(text: str) -> bool:
    return bool(re.search(r"(?is)<auth-user-pass>\s*\S+\s+\S+\s*</auth-user-pass>", text))


def auth_class(text: str) -> str:
    if has_inline_auth(text):
        return "embedded_credentials"
    if re.search(r"(?mi)^\s*auth-user-pass\b", text):
        return "username_password"
    if re.search(r"(?mi)^\s*(cert|key)\s+", text) or "<cert>" in text or "<key>" in text:
        return "certificate"
    return "anonymous"


def normalize_country(value: str | None) -> str | None:
    if not value:
        return None
    raw = value.strip()
    if len(raw) == 2 and raw.isalpha():
        return raw.upper()
    key = re.sub(r"[^a-z]", "", raw.lower())
    return COUNTRY_ALIASES.get(key)


def country_from_path(path: str) -> str | None:
    for part in [x for x in path.replace("\\", "/").split("/") if x]:
        code = normalize_country(part)
        if code:
            return code
        # filenames like JP_ASAHI... or server_10_JP.ovpn
        m = re.search(r"(?:^|[_-])([A-Za-z]{2})(?:[_-]|\.ovpn$)", part)
        if m:
            code = normalize_country(m.group(1))
            if code:
                return code
    return None


def country_priority(code: str | None) -> int:
    if code == "PL":
        return 300
    if code in EU_COUNTRIES:
        return 200
    if code:
        return 50
    return 0


def embed_public_auth(text: str, username: str, password: str) -> str:
    if has_inline_auth(text):
        return text
    cleaned = re.sub(r"(?mi)^\s*;?\s*auth-user-pass(?:\s+\S+)?\s*$\n?", "", text)
    block = f"<auth-user-pass>\n{username}\n{password}\n</auth-user-pass>\n"
    return cleaned.rstrip() + "\n\n" + block


def make_ready_config(text: str, source_id: str) -> tuple[str, str]:
    cls = auth_class(text)
    if cls in ("anonymous", "certificate", "embedded_credentials"):
        return text, cls

    if cls == "username_password" and source_id in KNOWN_PUBLIC_AUTH:
        user, password = KNOWN_PUBLIC_AUTH[source_id]
        ready = embed_public_auth(text, user, password)
        return ready, "embedded_credentials"

    return text, cls


def is_connect_ready(auth: str) -> bool:
    return auth in ("anonymous", "certificate", "embedded_credentials")


def parse_profile(text, source_id, source_url, name=""):
    host, port = parse_remote(text)
    if not host:
        return None
    proto = parse_proto(text)
    ready_text, auth = make_ready_config(text, source_id)
    return {
        "id": sha1_key(host, port, proto),
        "source": source_id,
        "source_url": source_url,
        "name": name or host,
        "host": host,
        "port": port,
        "proto": proto,
        "auth": auth,
        "config": ready_text,
    }


def tcp_probe(host, port, timeout=5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"reachable": True, "error": None}
    except Exception as exc:
        return {"reachable": False, "error": str(exc)}


def config_is_safe(cfg: str) -> bool:
    blocked = (
        "up ", "down ", "route-up ", "route-pre-down ", "ipchange ",
        "route-change ", "learn-address ", "client-connect ", "client-disconnect ",
        "plugin ", "tls-verify ", "management ", "config ", "askpass ",
        "auth-user-pass-verify ",
    )
    for raw in cfg.lower().splitlines():
        line = raw.strip()
        if any(line.startswith(d) for d in blocked):
            return False
    return True
