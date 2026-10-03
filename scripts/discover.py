from __future__ import annotations

import base64
import csv
import io
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (  # noqa: E402
    country_from_path,
    country_priority,
    get_json,
    is_connect_ready,
    normalize_country,
    parse_profile,
    save_json,
    session,
)

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "sources" / "sources.json"
OUT = ROOT / "data" / "discovered.json"

EU_FOCUS = [
    "poland", "germany", "netherlands", "france", "united-kingdom",
    "romania", "italy", "spain", "sweden", "denmark", "finland", "norway",
    "ukraine", "lithuania", "latvia", "estonia", "croatia", "czech-republic",
    "austria", "belgium", "portugal", "hungary", "slovakia",
]


def _decode_b64_config(b64: str) -> str | None:
    try:
        return base64.b64decode(b64.strip()).decode("utf-8", "replace")
    except Exception:
        return None


def _collect_ovpn_links(html: str, base_url: str) -> list[str]:
    patterns = [
        r'''href=["']([^"']+\.ovpn(?:\?[^"']*)?)["']''',
        r'''href=["']([^"']+/download/[^"']+)["']''',
        r'''href=["']([^"']*do_openvpn\.aspx[^"']*)["']''',
    ]
    found: list[str] = []
    for pat in patterns:
        for link in re.findall(pat, html, re.I):
            found.append(urljoin(base_url, link))
    # de-dupe preserving order
    return list(dict.fromkeys(found))


def vpngate_csv(source, s):
    records = []
    last_error = None
    for url in source.get("base_urls", []):
        try:
            r = s.get(url, timeout=45)
            r.raise_for_status()
            text = r.text
            lines = text.splitlines()
            header_idx = None
            for i, line in enumerate(lines):
                if "HostName" in line and "OpenVPN_ConfigData_Base64" in line:
                    header_idx = i
                    break
            if header_idx is None:
                raise RuntimeError(f"VPN Gate CSV header not found in {url}")

            header = lines[header_idx].lstrip("#")
            body = "\n".join(lines[header_idx + 1 :])
            reader = csv.DictReader(io.StringIO(header + "\n" + body))
            for row in reader:
                if not row:
                    continue
                hostname = (row.get("HostName") or "").strip()
                if not hostname or hostname.startswith("*"):
                    continue
                b64 = (row.get("OpenVPN_ConfigData_Base64") or "").strip()
                if not b64:
                    continue
                cfg = _decode_b64_config(b64)
                if not cfg:
                    continue
                p = parse_profile(cfg, source["id"], url, hostname)
                if not p:
                    continue
                p["country"] = normalize_country(row.get("CountryShort") or row.get("Country") or "")
                try:
                    p["latency_ms"] = int(row.get("Ping") or 0) or None
                except ValueError:
                    p["latency_ms"] = None
                try:
                    p["speed_kbps"] = int(row.get("Speed") or 0) or None
                except ValueError:
                    p["speed_kbps"] = None
                try:
                    p["score_upstream"] = int(row.get("Score") or 0) or None
                except ValueError:
                    p["score_upstream"] = None
                records.append(p)
            if records:
                return records
        except Exception as exc:
            last_error = exc
            print(f"[{source['id']}] fetch failed {url}: {exc}")
    if last_error and not records:
        raise last_error
    return records


def huntvpn_html(source, s):
    records = []
    r = s.get(source["base_urls"][0], timeout=30)
    r.raise_for_status()
    links = re.findall(r'href=["\']([^"\']*vpn/[^"\']+)["\']', r.text, re.I)
    for country_url in dict.fromkeys(urljoin(r.url, x) for x in links):
        try:
            page = s.get(country_url, timeout=30)
            page.raise_for_status()
            page_links = re.findall(r'''href=["']([^"']+\.ovpn(?:\?[^"']*)?)["']''', page.text, re.I)
            page_links += re.findall(r'''href=["']([^"']*/servers/[^"']+)["']''', page.text, re.I)
            for link in dict.fromkeys(page_links):
                url = urljoin(page.url, link)
                try:
                    target = s.get(url, timeout=20)
                    target.raise_for_status()
                    configs = re.findall(r'''href=["']([^"']+\.ovpn(?:\?[^"']*)?)["']''', target.text, re.I)
                    if configs:
                        for config_link in dict.fromkeys(configs):
                            cfg = s.get(urljoin(target.url, config_link), timeout=20)
                            cfg.raise_for_status()
                            p = parse_profile(cfg.text, source["id"], cfg.url)
                            if p:
                                p["country"] = country_from_path(page.url)
                                records.append(p)
                    else:
                        p = parse_profile(target.text, source["id"], target.url)
                        if p:
                            p["country"] = country_from_path(page.url)
                            records.append(p)
                except Exception as exc:
                    print(f"[{source['id']}] config/server failed: {url}: {exc}")
        except Exception as exc:
            print(f"[{source['id']}] page failed: {country_url}: {exc}")
    return records


def publicvpnlist_html(source, s):
    records = []
    for country in EU_FOCUS:
        page_url = urljoin(source["base_urls"][0], country + "/")
        try:
            page = s.get(page_url, timeout=30)
            page.raise_for_status()
            for link in dict.fromkeys(re.findall(r'''href=["']([^"']+\.ovpn(?:\?[^"']*)?)["']''', page.text, re.I)):
                url = urljoin(page.url, link)
                try:
                    cfg = s.get(url, timeout=20)
                    cfg.raise_for_status()
                    p = parse_profile(cfg.text, source["id"], url)
                    if p:
                        p["country"] = country_from_path(page.url) or normalize_country(country)
                        records.append(p)
                except Exception as exc:
                    print(f"[{source['id']}] config failed: {url}: {exc}")
        except Exception as exc:
            print(f"[{source['id']}] country failed: {country}: {exc}")
    return records


def generic_html_ovpn(source, s):
    """Scrape one or more HTML pages for direct .ovpn links and download them."""
    records = []
    max_files = int(source.get("max_files") or 120)
    country_hint = normalize_country(source.get("country_hint"))

    for page_url in source.get("base_urls", []):
        try:
            page = s.get(page_url, timeout=30)
            page.raise_for_status()
        except Exception as exc:
            print(f"[{source['id']}] page failed {page_url}: {exc}")
            continue

        links = _collect_ovpn_links(page.text, page.url)
        for url in links[:max_files]:
            try:
                cfg = s.get(url, timeout=20)
                cfg.raise_for_status()
                text = cfg.text
                # Skip HTML error pages mistaken for configs.
                if "<html" in text.lower()[:200] and "remote " not in text.lower():
                    continue
                name = Path(url.split("?")[0]).stem
                p = parse_profile(text, source["id"], url, name)
                if p:
                    p["country"] = country_from_path(url) or country_from_path(page_url) or country_hint
                    records.append(p)
            except Exception as exc:
                print(f"[{source['id']}] config failed: {url}: {exc}")
    return records


def _github_raw_base(api_tree_url: str) -> tuple[str, str, str]:
    m = re.search(r"api\.github\.com/repos/([^/]+)/([^/]+)/git/trees/([^/?]+)", api_tree_url)
    if not m:
        raise ValueError(f"Cannot parse GitHub tree URL: {api_tree_url}")
    return m.group(1), m.group(2), m.group(3)


def github_tree(source, s):
    records = []
    max_files = int(source.get("max_files") or 400)

    for tree_url in source.get("base_urls", []):
        try:
            owner, repo, branch = _github_raw_base(tree_url)
        except ValueError as exc:
            print(f"[{source['id']}] {exc}")
            continue

        try:
            r = s.get(tree_url, timeout=45)
            r.raise_for_status()
            tree = r.json().get("tree", [])
        except Exception as exc:
            print(f"[{source['id']}] tree failed {tree_url}: {exc}")
            continue

        def path_rank(path: str) -> int:
            return -country_priority(country_from_path(path))

        blobs = [
            item for item in tree
            if item.get("type") == "blob" and str(item.get("path", "")).lower().endswith(".ovpn")
        ]
        blobs.sort(key=lambda x: path_rank(x.get("path", "")))

        for item in blobs[:max_files]:
            path = item.get("path", "")
            url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
            try:
                cfg = s.get(url, timeout=20)
                cfg.raise_for_status()
                p = parse_profile(cfg.text, source["id"], url, Path(path).stem)
                if p:
                    p["country"] = country_from_path(path)
                    records.append(p)
            except Exception as exc:
                print(f"[{source['id']}] raw config failed: {path}: {exc}")
    return records


def main():
    cfg = get_json(CONFIG, {"sources": []})
    s = session()
    all_records = []

    for source in cfg["sources"]:
        if not source.get("enabled"):
            continue
        try:
            adapter = source["adapter"]
            if adapter == "vpngate_csv":
                records = vpngate_csv(source, s)
            elif adapter == "huntvpn_html":
                records = huntvpn_html(source, s)
            elif adapter == "publicvpnlist_html":
                records = publicvpnlist_html(source, s)
            elif adapter == "generic_html_ovpn":
                records = generic_html_ovpn(source, s)
            elif adapter == "github_tree":
                records = github_tree(source, s)
            else:
                records = []

            ready = [x for x in records if is_connect_ready(x.get("auth", ""))]
            skipped = len(records) - len(ready)
            for item in ready:
                item["source_priority"] = int(source.get("priority", 0)) + country_priority(item.get("country"))
            print(f"[{source['id']}] discovered={len(records)} ready={len(ready)} skipped_auth={skipped}")
            all_records.extend(ready)
        except Exception as exc:
            print(f"[{source['id']}] ERROR: {exc}")

    unique = {}
    for r in all_records:
        old = unique.get(r["id"])
        if old is None or r.get("source_priority", 0) > old.get("source_priority", 0):
            unique[r["id"]] = r

    ordered = sorted(
        unique.values(),
        key=lambda x: (
            -int(x.get("source_priority") or 0),
            -(x.get("speed_kbps") or 0),
            x.get("latency_ms") or 10**9,
            x.get("name") or "",
        ),
    )

    save_json(OUT, {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "servers": ordered,
    })
    print(f"total unique ready-to-connect: {len(ordered)}")


if __name__ == "__main__":
    main()
