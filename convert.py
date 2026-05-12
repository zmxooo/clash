import base64
import json
import yaml
import os
import re
import requests
from urllib.parse import urlparse, parse_qs, unquote

# ==========================================
# 地区识别
# ==========================================
def get_final_label(server, remarks=""):
    text = unquote(str(remarks)).lower()

    meta = [
        ("🇭🇰 香港节点", r"hk|香港|hongkong"),
        ("🇹🇼 台湾节点", r"tw|台湾|taiwan"),
        ("🇺🇸 美国节点", r"us|美国|america|unitedstates"),
        ("🇰🇷 韩国节点", r"kr|韩国|korea"),
        ("🇯🇵 日本节点", r"jp|日本|japan"),
        ("🇸🇬 新加坡节点", r"sg|新加坡|singapore"),
        ("🇩🇪 德国节点", r"de|德国|germany"),
        ("🇬🇧 英国节点", r"uk|gb|英国|britain"),
        ("🇻🇳 越南节点", r"vn|越南|vietnam"),
    ]

    for label, pattern in meta:
        if re.search(pattern, text):
            return label

    try:
        r = requests.get(
            f"http://ip-api.com/json/{server}?lang=zh-CN",
            timeout=3
        ).json()

        if r.get("status") == "success":
            country = r.get("country", "")

            mapping = {
                "香港": "🇭🇰 香港节点",
                "台湾": "🇹🇼 台湾节点",
                "美国": "🇺🇸 美国节点",
                "韩国": "🇰🇷 韩国节点",
                "日本": "🇯🇵 日本节点",
                "新加坡": "🇸🇬 新加坡节点",
                "德国": "🇩🇪 德国节点",
                "英国": "🇬🇧 英国节点",
                "越南": "🇻🇳 越南节点",
            }

            return mapping.get(country, "🧿 其它地区")

    except:
        pass

    return "🧿 其它地区"


# ==========================================
# Base64 安全解码
# ==========================================
def safe_dec(data):
    try:
        data = data.strip()
        data = data.replace("-", "+").replace("_", "/")
        data += "=" * (-len(data) % 4)
        return base64.b64decode(data).decode(
            "utf-8",
            errors="ignore"
        )
    except:
        return ""


# ==========================================
# VMESS 修复版
# ==========================================
def parse_vmess(link):
    try:
        raw = link.replace("vmess://", "").strip()

        if "#" in raw:
            raw = raw.split("#")[0]

        raw = raw.replace("-", "+").replace("_", "/")
        raw += "=" * (-len(raw) % 4)

        j = json.loads(
            base64.b64decode(raw).decode(
                "utf-8",
                errors="ignore"
            )
        )

        network = j.get("net", "tcp")

        node = {
            "label": get_final_label(
                j.get("add"),
                j.get("ps", "")
            ),
            "type": "vmess",
            "server": j.get("add"),
            "port": int(j.get("port", 443)),
            "uuid": j.get("id"),
            "alterId": int(
                j.get("aid", j.get("alterId", 0))
            ),
            "cipher": j.get("scy", "auto"),
            "udp": True,
            "tls": str(j.get("tls", "")).lower()
                   in ["tls", "true", "1"],
            "skip-cert-verify": True,
            "network": network
        }

        # websocket
        if network == "ws":
            node["ws-opts"] = {
                "path": j.get("path", "/"),
                "headers": {
                    "Host": j.get("host", "")
                }
            }

        # grpc
        elif network == "grpc":
            node["grpc-opts"] = {
                "grpc-service-name": j.get("path", "")
            }

        # http
        elif network == "http":
            node["http-opts"] = {
                "path": [j.get("path", "/")],
                "headers": {
                    "Host": [j.get("host", "")]
                }
            }

        return node

    except Exception as e:
        print("VMESS解析失败:", e)
        return None


# ==========================================
# 主解析器
# ==========================================
def parse_link(link):
    try:

        # VMESS
        if link.startswith("vmess://"):
            return parse_vmess(link)

        # VLESS / TROJAN
        elif link.startswith(("vless://", "trojan://")):

            u = urlparse(link)
            q = parse_qs(u.query)

            sni = q.get(
                "sni",
                q.get("host", [u.hostname])
            )[0]

            is_vless = link.startswith("vless://")

            node = {
                "label": get_final_label(
                    u.hostname,
                    u.fragment
                ),
                "type": "vless" if is_vless else "trojan",
                "server": u.hostname,
                "port": int(u.port or 443),
                "udp": True,
                "tls": True,
                "sni": sni,
                "skip-cert-verify": True
            }

            if is_vless:
                node["uuid"] = u.username
                node["cipher"] = "auto"
            else:
                node["password"] = u.username

            # ws
            if q.get("type", ["tcp"])[0] == "ws":
                node["network"] = "ws"
                node["ws-opts"] = {
                    "path": q.get("path", ["/"])[0],
                    "headers": {
                        "Host": sni
                    }
                }

            return node

        # SS
        elif link.startswith("ss://"):

            raw = link[5:]

            if "#" in raw:
                raw = raw.split("#")[0]

            if "@" not in raw:
                raw = safe_dec(raw)

            userinfo, server = raw.split("@", 1)

            if ":" not in userinfo:
                userinfo = safe_dec(userinfo)

            method, password = userinfo.split(":", 1)

            host, port = server.rsplit(":", 1)

            return {
                "label": get_final_label(host),
                "type": "ss",
                "server": host,
                "port": int(port),
                "cipher": method,
                "password": password,
                "udp": True
            }

        # HY2
        elif link.startswith(("hy2://", "hysteria2://")):

            u = urlparse(link)

            return {
                "label": get_final_label(
                    u.hostname,
                    u.fragment
                ),
                "type": "hysteria2",
                "server": u.hostname,
                "port": int(u.port or 443),
                "password": u.username,
                "sni": u.hostname,
                "skip-cert-verify": True,
                "udp": True
            }

    except Exception as e:
        print("解析失败:", e)

    return None


# ==========================================
# 主程序
# ==========================================
def main():

    if not os.path.exists("nodes.txt"):
        print("❌ nodes.txt 不存在")
        return

    with open(
        "nodes.txt",
        "r",
        encoding="utf-8"
    ) as f:

        content = f.read()

    # 自动提取节点
    links = re.findall(
        r'(vmess|vless|trojan|ss|hy2|hysteria2)://[^\s]+',
        content
    )

    # 修复 re.findall 返回 tuple 问题
    links = re.findall(
        r'(?:vmess|vless|trojan|ss|hy2|hysteria2)://[^\s]+',
        content
    )

    proxies = []
    region_map = {}

    for link in links:

        node = parse_link(link)

        if not node:
            continue

        label = node.pop("label")

        if label not in region_map:
            region_map[label] = []

        idx = len(region_map[label]) + 1

        node["name"] = f"{label} @zmxooo {idx:02d}"

        region_map[label].append(node["name"])

        proxies.append(node)

    if not proxies:
        print("⚠️ 没有解析出节点")
        return

    print(f"✅ 成功解析 {len(proxies)} 个节点")

    regions = [
        "🇭🇰 香港节点",
        "🇹🇼 台湾节点",
        "🇯🇵 日本节点",
        "🇸🇬 新加坡节点",
        "🇰🇷 韩国节点",
        "🇺🇸 美国节点",
        "🇩🇪 德国节点",
        "🇬🇧 英国节点",
        "🧿 其它地区"
    ]

    groups = []

    for r in regions:

        groups.append({
            "name": r,
            "type": "url-test",
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 50,
            "proxies": region_map.get(r, ["DIRECT"])
        })

    config = {
        "mixed-port": 7890,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "ipv6": False,

        "tun": {
            "enable": True,
            "stack": "mixed",
            "auto-route": True,
            "auto-detect-interface": True
        },

        "dns": {
            "enable": True,
            "listen": "0.0.0.0:53",
            "enhanced-mode": "fake-ip",
            "ipv6": False,
            "nameserver": [
                "223.5.5.5",
                "119.29.29.29",
                "8.8.8.8"
            ]
        },

        "proxies": proxies,

        "proxy-groups": [

            {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": [
                    "⚡ 自动选择"
                ] + regions
            },

            {
                "name": "⚡ 自动选择",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": [
                    p["name"] for p in proxies
                ]
            },

        ] + groups,

        "rules": [
            "DOMAIN-SUFFIX,google.com,🚀 节点选择",
            "DOMAIN-SUFFIX,youtube.com,🚀 节点选择",
            "DOMAIN-SUFFIX,openai.com,🚀 节点选择",
            "DOMAIN-SUFFIX,chatgpt.com,🚀 节点选择",
            "GEOIP,CN,DIRECT",
            "MATCH,🚀 节点选择"
        ]
    }

    with open(
        "config.yaml",
        "w",
        encoding="utf-8"
    ) as f:

        yaml.dump(
            config,
            f,
            allow_unicode=True,
            sort_keys=False
        )

    print("🎉 已生成 config.yaml")


if __name__ == "__main__":
    main()
