from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DATA, config_is_safe, get_json, is_connect_ready, save_json, tcp_probe  # noqa: E402

INPUT = DATA / "discovered.json"
OUTPUT = DATA / "validated.json"
WORKING_TTL_HOURS = 24
FAILED_TTL_HOURS = 6
TCP_WORKERS = 16
# Cap expensive OpenVPN handshakes per run so Actions stays under timeout.
MAX_HANDSHAKES_PER_RUN = 80


def config_hash(cfg):
    return hashlib.sha256(cfg.encode("utf-8")).hexdigest()


def fresh_enough(old, ttl_hours):
    stamp = old.get("checked_at")
    if not stamp:
        return False
    try:
        checked = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - checked).total_seconds() < ttl_hours * 3600
    except Exception:
        return False


def extract_inline_auth(cfg: str):
    m = re.search(r"(?is)<auth-user-pass>\s*(\S+)\s+(\S+)\s*</auth-user-pass>", cfg)
    if not m:
        return None, None
    return m.group(1), m.group(2)


def openvpn_handshake(profile):
    cfg = profile.get("config")
    if not cfg:
        return {"status": "not_tested", "error": "raw config unavailable"}
    if not config_is_safe(cfg):
        return {"status": "rejected", "error": "config contains a blocked executable directive"}
    if not is_connect_ready(profile.get("auth", "")):
        return {"status": "credentials_required", "error": "profile is not connect-ready"}

    proc = None
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "profile.ovpn"
        path.write_text(cfg, encoding="utf-8")
        cmd = [
            "sudo", "openvpn",
            "--config", str(path),
            "--connect-timeout", "12",
            "--connect-retry-max", "1",
            "--ping-exit", "10",
            "--verb", "3",
        ]

        # Prefer credentials already embedded in the profile.
        user, password = extract_inline_auth(cfg)
        if not user or not password:
            user = os.getenv("VPNONLINE_USERNAME")
            password = os.getenv("VPNONLINE_PASSWORD")

        auth_file = None
        if user and password and not extract_inline_auth(cfg):
            auth_file = Path(td) / "auth.txt"
            auth_file.write_text(user + "\n" + password + "\n", encoding="utf-8")
            auth_file.chmod(0o600)
            cmd += ["--auth-user-pass", str(auth_file)]

        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
            )
            started = time.monotonic()
            output = []
            connected = False
            while time.monotonic() - started < 18:
                line = proc.stdout.readline()
                if line:
                    output.append(line)
                    low = line.lower()
                    if "initialization sequence completed" in low:
                        connected = True
                        break
                    if "auth_failed" in low or "authentication failed" in low:
                        break
                elif proc.poll() is not None:
                    break

            if connected:
                time.sleep(1)
                ip = None
                try:
                    import requests

                    rr = requests.get("https://api.ipify.org?format=json", timeout=5)
                    if rr.ok:
                        ip = rr.json().get("ip")
                except Exception:
                    pass
                return {
                    "status": "working",
                    "error": None,
                    "exit_ip": ip,
                    "handshake_ms": int((time.monotonic() - started) * 1000),
                }

            text = "".join(output).lower()
            if "auth_failed" in text or "authentication failed" in text:
                return {"status": "auth_failed", "error": "authentication failed"}
            if "tls error" in text or "tls key negotiation failed" in text:
                return {"status": "tls_failed", "error": "tls handshake failed"}
            return {"status": "failed", "error": text[-1200:]}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}
        finally:
            if proc:
                try:
                    proc.terminate()
                    proc.wait(timeout=3)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass


def main():
    data = get_json(INPUT, {"servers": []})
    history = get_json(DATA / "history.json", {"servers": {}})
    old_history = history["servers"]
    out = []
    now = datetime.now(timezone.utc).isoformat()
    tcp_results = {}

    def probe(p):
        return p["id"], tcp_probe(p["host"], p["port"])

    with ThreadPoolExecutor(max_workers=TCP_WORKERS) as pool:
        for pid, result in pool.map(probe, data["servers"]):
            tcp_results[pid] = result

    reused = 0
    checked = 0
    handshakes = 0

    for index, p in enumerate(data["servers"], 1):
        old = old_history.get(p["id"], {})
        cfg = p.get("config", "")
        cfg_sha = config_hash(cfg)
        ttl = WORKING_TTL_HOURS if old.get("status") == "working" else FAILED_TTL_HOURS

        if old.get("config_sha256") == cfg_sha and fresh_enough(old, ttl):
            record = dict(old)
            for key in (
                "source", "source_url", "name", "host", "port", "proto", "auth",
                "country", "source_priority", "latency_ms", "speed_kbps",
            ):
                if key in p:
                    record[key] = p[key]
            record["config_sha256"] = cfg_sha
            record["last_seen"] = now
            out.append(record)
            old_history[p["id"]] = record
            reused += 1
            continue

        tcp = tcp_results[p["id"]]
        record = {k: v for k, v in p.items() if k != "config"}
        record["checked_at"] = now
        record["tcp"] = tcp
        record["config_sha256"] = cfg_sha

        if not tcp["reachable"]:
            record["status"] = "unreachable"
            record["handshake"] = {"status": "not_tested", "error": "tcp unreachable"}
        elif not is_connect_ready(p.get("auth", "")):
            record["status"] = "credentials_required"
            record["handshake"] = {"status": "not_tested", "error": "not connect-ready"}
        elif handshakes >= MAX_HANDSHAKES_PER_RUN:
            # Keep previous result if any; otherwise mark deferred.
            if old.get("status") == "working" and old.get("config_sha256") == cfg_sha:
                record = dict(old)
                record["last_seen"] = now
                out.append(record)
                old_history[p["id"]] = record
                continue
            record["status"] = "deferred"
            record["handshake"] = {"status": "not_tested", "error": "handshake budget exceeded"}
        else:
            record["handshake"] = openvpn_handshake(p)
            record["status"] = record["handshake"]["status"]
            handshakes += 1

        failures = int(old.get("consecutive_failures", 0))
        failures = 0 if record["status"] == "working" else failures + 1
        record["consecutive_failures"] = failures
        if record["status"] == "working":
            record["lifecycle"] = "working"
        elif failures >= 12:
            record["lifecycle"] = "dead"
        elif failures >= 4:
            record["lifecycle"] = "quarantine"
        else:
            record["lifecycle"] = "temporarily_failed"

        record["first_seen"] = old.get("first_seen", now)
        record["last_seen"] = now
        old_history[p["id"]] = record
        out.append(record)
        checked += 1

        if index % 25 == 0 or index == len(data["servers"]):
            print(
                f"progress {index}/{len(data['servers'])}; "
                f"reused={reused}; checked={checked}; handshakes={handshakes}"
            )

    save_json(OUTPUT, {"generated_at": now, "servers": out})
    save_json(DATA / "history.json", history)
    working = sum(x["status"] == "working" for x in out)
    print(
        f"validated {len(out)} servers; working={working}; "
        f"reused={reused}; checked={checked}; handshakes={handshakes}"
    )


if __name__ == "__main__":
    main()
