#!/usr/bin/env python3
import argparse
import base64
import ipaddress
import json
import re
import socket
import sys
import time
import urllib.parse
import urllib.request

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

IGARECK = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main"
WHITE_FILES = ["WHITE-CIDR-RU-checked.txt", "WHITE-CIDR-RU-all.txt", "Vless-Reality-White-Lists-Rus-Mobile.txt"]
BLACK_FILES = ["BLACK_VLESS_RUS_mobile.txt"]
SNI_FILES = ["WHITE-SNI-RU-all.txt"]
KORT0881_WHITELIST = "https://raw.githubusercontent.com/kort0881/russia-whitelist/main/whitelist.txt"

POOL_SOURCES = [
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/sub_merge_base64.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/sub/v2raysub",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription_collection",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/base64/donated",
    "https://raw.githubusercontent.com/Barry-Far/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/vpei/Free-Node-Merge/main/o/node.txt",
]

def fetch(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def decoders(url, data):
    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        return []
    if "://" in text and not text.startswith("#"):
        return [text]
    try:
        text = base64.b64decode(re.sub(r"\s+", "", text)).decode("utf-8", errors="ignore")
    except Exception:
        pass
    return [text]


def uris_from(text):
    return re.findall(r"(?:vless|vmess|trojan|hysteria2|hy2|ss)://[^\s\"'<>#]+", text)


def host_ips(host):
    try:
        ip = ipaddress.ip_address(host)
        return [str(ip)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
        return [i[4][0] for i in infos if ":" not in i[4][0]] or []
    except Exception:
        return []


def cidr24(ip):
    try:
        a = ipaddress.ip_address(ip)
        if a.version == 4:
            return ipaddress.ip_network(ip + "/24", strict=False)
    except Exception:
        pass
    return None


def parse_uri(u):
    m = re.match(r"^([a-z0-9]+)://(?:([^@/]+)@)?([^/?#:]+)(?::(\d+))?", u)
    if not m:
        return None
    scheme, cred, host, port = m.groups()
    q = {}
    qs = u.split("?")
    if len(qs) > 1:
        qm = re.search(r"(.*?)(?:#|$)", qs[1])
        for kv in qm.group(1).split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                q[k] = v
    name = u.rsplit("#", 1)[1] if "#" in u else ""
    try:
        name = urllib.parse.unquote(name)
    except Exception:
        pass
    return {
        "scheme": scheme,
        "host": host,
        "port": int(port or (443 if scheme in ("vless", "vmess", "trojan", "ss") else 443)),
        "name": name,
        "sni": (q.get("sni") or q.get("host") or "").lower(),
        "path": q.get("path", "").lower(),
    }


def load_oracle_files(cache_dir):
    white_24, black_24, sni = set(), set(), set()
    white_uris = set()
    for f in WHITE_FILES:
        data = None
        if cache_dir:
            try:
                data = open(cache_dir + "/" + f, "rb").read()
            except OSError:
                data = None
        if data is None:
            data = fetch(f"{IGARECK}/{f}")
        for text in decoders(f, data):
            for u in uris_from(text):
                white_uris.add(u)
                p = parse_uri(u)
                if p:
                    sni.add(p["sni"]) if p["sni"] else None
                    for ip in host_ips(p["host"]):
                        c = cidr24(ip)
                        if c:
                            white_24.add(c)
    black_uris = set()
    for f in BLACK_FILES:
        data = None
        if cache_dir:
            try:
                data = open(cache_dir + "/" + f, "rb").read()
            except OSError:
                data = None
        if data is None:
            data = fetch(f"{IGARECK}/{f}")
        for text in decoders(f, data):
            for u in uris_from(text):
                black_uris.add(u)
                p = parse_uri(u)
                if p:
                    for ip in host_ips(p["host"]):
                        c = cidr24(ip)
                        if c:
                            black_24.add(c)
    for f in SNI_FILES:
        data = None
        if cache_dir:
            try:
                data = open(cache_dir + "/" + f, "rb").read()
            except OSError:
                data = None
        if data is None:
            data = fetch(f"{IGARECK}/{f}")
        for text in decoders(f, data):
            for m in re.findall(r"([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?::\d+)?", text.lower()):
                sni.add(m)
    try:
        data = fetch(KORT0881_WHITELIST)
        for m in re.findall(r"^\s*([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?::\d+)?\s*#?", data.decode("utf-8", errors="ignore"), re.M):
            sni.add(m.strip().lower().split("#")[0].strip())
    except Exception:
        pass
    return white_24, black_24, sni, white_uris, black_uris


def load_pool(cache_dir, extra_pools):
    src = {}
    for name, url in [("igareck_checked", f"{IGARECK}/WHITE-CIDR-RU-checked.txt"),
                      ("igareck_all", f"{IGARECK}/WHITE-CIDR-RU-all.txt"),
                      ("igareck_mobile", f"{IGARECK}/Vless-Reality-White-Lists-Rus-Mobile.txt")] + \
                     [(u.rsplit("/", 1)[-1], u) for u in POOL_SOURCES]:
        data = None
        if cache_dir:
            try:
                data = open(cache_dir + "/" + name, "rb").read()
            except OSError:
                data = None
        if data is None:
            try:
                data = fetch(url)
            except Exception as e:
                print(f"  ! {name}: {e}")
                continue
        for text in decoders(url, data):
            for u in uris_from(text):
                if u not in src:
                    src[u] = name
        print(f"  {name}: ok")
    for p in extra_pools or []:
        for line in open(p, encoding="utf-8", errors="ignore"):
            for u in uris_from(line):
                if u not in src:
                    src[u] = "local:" + p
    return src


def classify(uri, white_24, black_24, sni, white_uris, black_uris):
    p = parse_uri(uri)
    if not p:
        return None
    if uri in white_uris:
        return {"mobile": True, "via": "in_community_white_list", "details": []}
    if uri in black_uris:
        return {"mobile": False, "via": "in_community_black_list", "details": []}
    hit_w, hit_b, reason = [], [], []
    for ip in host_ips(p["host"]):
        c = cidr24(ip)
        if c in white_24:
            hit_w.append(str(c.network_address)); reason.append(f"cidr_white:{ip}")
        if c in black_24:
            hit_b.append(str(c.network_address)); reason.append(f"cidr_black:{ip}")
    if p["sni"] and (p["sni"] in sni or p["host"] in sni):
        reason.append(f"sni_white:{p['sni']}")
    if not hit_b and hit_w:
        return {"mobile": True, "via": "cidr_white", "details": reason}
    if hit_b:
        return {"mobile": False, "via": "cidr_black", "details": reason}
    if p["sni"] and p["sni"] in sni:
        return {"mobile": True, "via": "sni_white", "details": reason}
    return {"mobile": None, "via": "unknown", "details": reason}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache-dir", default=None)
    ap.add_argument("--pool", action="append", default=[])
    ap.add_argument("--push", action="store_true")
    ap.add_argument("--token", default=None)
    ap.add_argument("--repo", default="cibin2004/sub")
    ap.add_argument("--branch", default="main")
    args = ap.parse_args()

    t0 = time.time()
    print("[1/3] loading whitelist oracles (igareck + kort0881)...")
    white_24, black_24, sni, white_uris, black_uris = load_oracle_files(args.cache_dir)
    print(f"  white /24: {len(white_24)}  black /24: {len(black_24)}  white SNI: {len(sni)}  white uris: {len(white_uris)}")

    print("[2/3] loading node pool...")
    src = load_pool(args.cache_dir, args.pool)
    print(f"  pool uris: {len(src)}")

    print("[3/3] classifying...")
    mobile, seen = [], set()
    n_black = n_unknown = 0
    report = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "white_24_count": len(white_24), "black_24_count": len(black_24),
              "sni_count": len(sni), "pool_count": len(src),
              "nodes": []}
    for uri, srcname in sorted(src.items(), key=lambda kv: kv[0]):
        key = uri.split("#")[0]
        if key in seen:
            continue
        seen.add(key)
        c = classify(uri, white_24, black_24, sni, white_uris, black_uris)
        if c is None:
            continue
        rec = {"uri": uri, "source": srcname,
               "mobile": c["mobile"], "via": c["via"], "details": c["details"]}
        report["nodes"].append(rec)
        if c["mobile"]:
            mobile.append(uri)
        elif c["mobile"] is False:
            n_black += 1
        else:
            n_unknown += 1

    mobile = sorted(set(mobile), key=lambda u: u)
    b64 = base64.b64encode("\n".join(mobile).encode()).decode()
    report["mobile_count"] = len(mobile)
    report["black_count"] = n_black
    report["unknown_count"] = n_unknown
    print(f"  mobile: {len(mobile)}  black: {n_black}  unknown: {n_unknown}  ({time.time()-t0:.1f}s)")
    for u in mobile:
        p = parse_uri(u)
        print(f"   + {p['scheme']}://{p['host']}:{p['port']}  {p['name'][:40]}")

    open("mobile.txt", "w").write(b64)
    open("mobile_plain.txt", "w").write("\n".join(mobile) + "\n")
    json.dump(report, open("mobile_report.json", "w"), ensure_ascii=False, indent=1)

    if args.push:
        token = args.token or __import__("os").environ.get("GH_TOKEN")
        if not token:
            print("no token for --push")
            return
        H = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json", "User-Agent": "curl"}
        import os
        for path in ("mobile.txt", "mobile_plain.txt", "mobile_report.json"):
            content = base64.b64encode(open(path, "rb").read()).decode()
            url = f"https://api.github.com/repos/{args.repo}/contents/{path}"
            req = urllib.request.Request(url, headers=H, method="GET")
            sha = None
            try:
                with urllib.request.urlopen(req, timeout=15) as r:
                    sha = json.loads(r.read()).get("sha")
            except Exception:
                pass
            body = {"message": f"auto mobile check: {len(mobile)} nodes", "content": content, "branch": args.branch}
            if sha:
                body["sha"] = sha
            req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=H, method="PUT")
            try:
                with urllib.request.urlopen(req, timeout=20) as r:
                    print(f"  pushed {path}: {r.status}")
            except Exception as e:
                print(f"  push {path}: ERR {e}")


if __name__ == "__main__":
    main()