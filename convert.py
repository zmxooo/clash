import base64
import json
import urllib.parse
import os
import re
import requests
import time
import yaml
from collections import defaultdict

CHANNEL_MARK = "@zmxooo"

IP_CACHE = {}

EMOJI_MAP = {
    "香港": "🇭🇰",
    "台湾": "🇹🇼",
    "美国": "🇺🇸",
    "英国": "🇬🇧",
    "韩国": "🇰🇷",
    "日本": "🇯🇵",
    "新加坡": "🇸🇬",
    "越南": "🇻🇳",
    "德国": "🇩🇪",
    "立陶宛": "🇱🇹",
    "法国": "🇫🇷",
    "俄罗斯": "🇷🇺",
    "加拿大": "🇨🇦",
    "荷兰": "🇳🇱",
    "澳大利亚": "🇦🇺",
    "阿联酋": "🇦🇪",
    "土耳其": "🇹🇷",
}


# ==================== BASE64 ====================

def parse_base64(data: str):
    try:
        data = re.sub(r'[^A-Za-z0-9+/=_-]', '', str(data))
        data = data.replace('-', '+').replace('_', '/')

        padding = len(data) % 4
        if padding:
            data += '=' * (4 - padding)

        return base64.b64decode(data)

    except:
        return b''


# ==================== 安全转换 ====================

def safe_int(val, default=443):
    try:
        if isinstance(val, int):
            return val

        val = re.sub(r'\D', '', str(val))
        return int(val) if val else default

    except:
        return default


# ==================== 清理 SNI ====================

def clean_sni(sni: str):
    if not sni:
        return ""

    sni = urllib.parse.unquote(str(sni)).strip()

    if "://" in sni:
        sni = sni.split("://", 1)[1]

    sni = sni.split('/')[0]

    return sni


# ==================== 清理 URL fragment ====================

def clean_base_uri(link: str):
    parsed = urllib.parse.urlparse(link)

    return urllib.parse.urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            '',
            parsed.query,
            ''
        )
    )


# ==================== 国家识别 ====================

def get_country_label(server: str, remarks: str = ""):
    text = urllib.parse.unquote(str(remarks)).lower()

    rules = [
        ("香港", r"hk|hongkong|香港"),
        ("台湾", r"tw|taiwan|台灣|台湾"),
        ("美国", r"us|unitedstates|美国|美國"),
        ("英国", r"gb|uk|britain|英国|英國"),
        ("韩国", r"kr|korea|韩国|韓國"),
        ("日本", r"jp|japan|日本"),
        ("新加坡", r"sg|singapore|新加坡"),
        ("德国", r"de|germany|德国"),
        ("立陶宛", r"lt|lithuania|立陶宛"),
    ]

    for country, pattern in rules:
        if re.search(pattern, text):
            return f"{EMOJI_MAP.get(country, '🌍')} {country}"

    if server and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', server):

        if server in IP_CACHE:
            return IP_CACHE[server]

        try:
            time.sleep(0.05)

            resp = requests.get(
                f"http://ip-api.com/json/{server}?lang=zh-CN",
                timeout=3
            )

            data = resp.json()

            if data.get("status") == "success":

                country = data.get("country", "其他地区")

                label = f"{EMOJI_MAP.get(country, '🌍')} {country}"

                IP_CACHE[server] = label

                return label

        except:
            pass

    return "🧿 其他地区"


# ==================== VMESS ====================

def parse_vmess(link: str):

    try:
        raw = link[8:].split('#')[0]

        decoded = parse_base64(raw)

        if not decoded:
            return None

        data = json.loads(decoded.decode('utf-8', 'ignore'))

        return {
            "type": "vmess",
            "data": data,
            "server": data.get("add"),
            "remarks": data.get("ps", "")
        }

    except:
        return None


# ==================== HYSTERIA ====================

def parse_hysteria(link: str):

    try:
        parsed = urllib.parse.urlparse(link)

        query = urllib.parse.parse_qs(parsed.query)

        proto = "hysteria2" if parsed.scheme in [
            "hy2",
            "hysteria2"
        ] else "hysteria"

        sni = clean_sni(
            query.get("sni", [parsed.hostname])[0]
        )

        return {
            "type": proto,
            "server": parsed.hostname,
            "port": parsed.port or 443,
            "password": parsed.username or "",
            "query": query,
            "sni": sni,
            "raw_link": link,
            "remarks": parsed.fragment
        }

    except:
        return None


# ==================== 标准协议 ====================

def parse_standard(link: str):

    try:
        parsed = urllib.parse.urlparse(link)

        return {
            "type": parsed.scheme,
            "server": parsed.hostname,
            "url": parsed,
            "query": urllib.parse.parse_qs(parsed.query),
            "raw_link": link,
            "remarks": parsed.fragment
        }

    except:
        return None


# ==================== 协议识别 ====================

def parse_link(link: str):

    link = link.strip()

    if not link:
        return None

    try:

        if link.startswith("vmess://"):
            return parse_vmess(link)

        elif link.startswith((
                "hy2://",
                "hysteria://",
                "hysteria2://"
        )):
            return parse_hysteria(link)

        elif link.startswith((
                "ss://",
                "trojan://",
                "vless://"
        )):
            return parse_standard(link)

    except:
        return None

    return None


# ==================== VMESS -> CLASH ====================

def build_vmess_clash(node_name, data):

    network = data.get("net", "tcp")

    proxy = {
        "name": node_name,
        "type": "vmess",
        "server": data.get("add", "127.0.0.1"),
        "port": safe_int(data.get("port"), 443),
        "uuid": data.get("id", ""),
        "alterId": safe_int(data.get("aid"), 0),
        "cipher": "auto",
        "udp": True,
        "tls": str(data.get("tls", "")).lower() in [
            "tls",
            "1",
            "true"
        ],
        "skip-cert-verify": True,
        "network": network
    }

    host = data.get("host", "")
    path = data.get("path", "/")

    if host:
        proxy["servername"] = host

    if network == "ws":

        proxy["ws-opts"] = {
            "path": path,
            "headers": {
                "Host": host
            }
        }

    elif network == "grpc":

        proxy["grpc-opts"] = {
            "grpc-service-name": path
        }

    elif network == "h2":

        proxy["h2-opts"] = {
            "host": [host] if host else [],
            "path": path
        }

    return proxy


# ==================== VLESS -> CLASH ====================

def build_vless_clash(node_name, parsed):

    u = parsed["url"]
    q = parsed["query"]

    security = q.get("security", [""])[0]

    network = q.get("type", ["tcp"])[0]

    proxy = {
        "name": node_name,
        "type": "vless",
        "server": u.hostname or "127.0.0.1",
        "port": safe_int(u.port, 443),
        "uuid": u.username or "",
        "udp": True,
        "tls": security in ["tls", "reality"],
        "network": network,
        "skip-cert-verify": True
    }

    if q.get("sni"):
        proxy["servername"] = q["sni"][0]

    if network == "ws":

        proxy["ws-opts"] = {
            "path": q.get("path", ["/"])[0],
            "headers": {
                "Host": q.get("host", [""])[0]
            }
        }

    if security == "reality":

        proxy["reality-opts"] = {
            "public-key": q.get("pbk", [""])[0],
            "short-id": q.get("sid", [""])[0]
        }

        proxy["client-fingerprint"] = q.get(
            "fp",
            ["chrome"]
        )[0]

    return proxy


# ==================== TROJAN -> CLASH ====================

def build_trojan_clash(node_name, parsed):

    u = parsed["url"]
    q = parsed["query"]

    proxy = {
        "name": node_name,
        "type": "trojan",
        "server": u.hostname or "127.0.0.1",
        "port": safe_int(u.port, 443),
        "password": u.username or "",
        "udp": True,
        "skip-cert-verify": True,
        "sni": q.get("sni", [u.hostname])[0]
    }

    return proxy


# ==================== SS -> CLASH ====================

def build_ss_clash(node_name, parsed):

    u = parsed["url"]

    method = "aes-256-gcm"
    password = ""
    server = u.hostname
    port = safe_int(u.port, 443)

    try:

        if '@' in u.netloc:

            userinfo = u.netloc.split('@')[0]

            if ':' in userinfo:

                method, password = userinfo.split(':', 1)

            else:

                decoded = parse_base64(
                    userinfo
                ).decode(
                    'utf-8',
                    'ignore'
                )

                method, password = decoded.split(':', 1)

        else:

            decoded = parse_base64(
                u.netloc
            ).decode(
                'utf-8',
                'ignore'
            )

            if '@' in decoded:

                userinfo, hostinfo = decoded.split('@', 1)

                method, password = userinfo.split(':', 1)

                if ':' in hostinfo:

                    server, p = hostinfo.rsplit(':', 1)

                    port = safe_int(p, 443)

    except:
        pass

    return {
        "name": node_name,
        "type": "ss",
        "server": server or "127.0.0.1",
        "port": port,
        "cipher": method,
        "password": password,
        "udp": True
    }


# ==================== 主程序 ====================

def main():

    if not os.path.exists("nodes.txt"):
        print("❌ 未找到 nodes.txt")
        return

    with open(
            "nodes.txt",
            "r",
            encoding="utf-8",
            errors="ignore"
    ) as f:

        raw_lines = [
            x.strip()
            for x in f
            if x.strip()
        ]

    # 去重
    seen = set()
    unique_links = []

    for line in raw_lines:

        core = clean_base_uri(line)

        if core not in seen:

            seen.add(core)

            unique_links.append(line)

    print(f"🔄 去重后节点数量: {len(unique_links)}")

    region_map = defaultdict(list)

    rocket_links = []

    clash_proxies = []

    # ==================== 开始处理 ====================

    for link in unique_links:

        parsed = parse_link(link)

        if not parsed:
            continue

        label = get_country_label(
            parsed.get("server"),
            parsed.get("remarks", "")
        )

        idx = len(region_map[label]) + 1

        node_name = f"{label} {idx:02d} {CHANNEL_MARK}"

        region_map[label].append(node_name)

        try:

            # ==================== VMESS ====================

            if parsed["type"] == "vmess":

                data = parsed["data"].copy()

                data["ps"] = node_name

                vmess_json = json.dumps(
                    data,
                    ensure_ascii=False,
                    separators=(',', ':')
                )

                vmess_b64 = base64.b64encode(
                    vmess_json.encode('utf-8')
                ).decode()

                rocket_links.append(
                    f"vmess://{vmess_b64}"
                )

                clash_proxies.append(
                    build_vmess_clash(
                        node_name,
                        data
                    )
                )

            # ==================== HYSTERIA ====================

            elif parsed["type"] in [
                "hysteria",
                "hysteria2"
            ]:

                query = parsed["query"]

                query["sni"] = [parsed["sni"]]

                query["insecure"] = ["1"]

                new_query = urllib.parse.urlencode(
                    query,
                    doseq=True
                )

                prefix = (
                    "hy2"
                    if parsed["type"] == "hysteria2"
                    else "hysteria"
                )

                rebuilt = (
                    f"{prefix}://"
                    f"{parsed['password']}@"
                    f"{parsed['server']}:"
                    f"{parsed['port']}?"
                    f"{new_query}"
                    f"#{urllib.parse.quote(node_name)}"
                )

                rocket_links.append(rebuilt)

                clash_node = {
                    "name": node_name,
                    "type": parsed["type"],
                    "server": parsed["server"],
                    "port": parsed["port"],
                    "password": parsed["password"],
                    "sni": parsed["sni"],
                    "skip-cert-verify": True,
                    "alpn": ["h3"]
                }

                if parsed["type"] == "hysteria":

                    clash_node["auth-str"] = parsed["password"]

                clash_proxies.append(clash_node)

            # ==================== VLESS ====================

            elif parsed["type"] == "vless":

                base_uri = clean_base_uri(link)

                rocket_links.append(
                    f"{base_uri}"
                    f"#{urllib.parse.quote(node_name)}"
                )

                clash_proxies.append(
                    build_vless_clash(
                        node_name,
                        parsed
                    )
                )

            # ==================== TROJAN ====================

            elif parsed["type"] == "trojan":

                base_uri = clean_base_uri(link)

                rocket_links.append(
                    f"{base_uri}"
                    f"#{urllib.parse.quote(node_name)}"
                )

                clash_proxies.append(
                    build_trojan_clash(
                        node_name,
                        parsed
                    )
                )

            # ==================== SS ====================

            elif parsed["type"] == "ss":

                base_uri = clean_base_uri(link)

                rocket_links.append(
                    f"{base_uri}"
                    f"#{urllib.parse.quote(node_name)}"
                )

                clash_proxies.append(
                    build_ss_clash(
                        node_name,
                        parsed
                    )
                )

        except Exception as e:

            print(f"⚠️ 节点解析失败: {e}")

            continue

    # ==================== 导出 ====================

    try:

        rocket_raw = '\n'.join(rocket_links)

        rocket_b64 = base64.b64encode(
            rocket_raw.encode('utf-8')
        ).decode('utf-8')

        with open(
                "rocket_output.txt",
                "w",
                encoding="utf-8"
        ) as f:

            f.write(rocket_b64)

        clash_config = {
            "proxies": clash_proxies
        }

        with open(
                "clash_output.yaml",
                "w",
                encoding="utf-8"
        ) as f:

            yaml.dump(
                clash_config,
                f,
                allow_unicode=True,
                sort_keys=False
            )

        print("\n✅ 修复完成")
        print(f"✅ Clash 节点数量: {len(clash_proxies)}")
        print(f"✅ Rocket 节点数量: {len(rocket_links)}")
        print("✅ 已输出 clash_output.yaml")
        print("✅ 已输出 rocket_output.txt")

    except Exception as e:

        print(f"❌ 输出失败: {e}")


# ==================== 入口 ====================

if __name__ == "__main__":
    main()
