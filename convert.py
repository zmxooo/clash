import base64
import json
import yaml
import os
import re
import requests
from urllib.parse import urlparse, parse_qs, unquote

# =========================
# Base64 解码
# =========================
def safe_dec(d):

    try:

        d = d.strip()

        d = d.replace("-", "+")
        d = d.replace("_", "/")

        padding = len(d) % 4

        if padding:
            d += "=" * (4 - padding)

        return base64.b64decode(
            d
        ).decode(
            "utf-8",
            errors="ignore"
        )

    except:

        return ""

# =========================
# 地区识别
# =========================
def get_final_label(server, remarks=""):

    text = unquote(str(remarks)).lower()

    meta = [

        ("🇭🇰 香港节点", r"hk|香港"),
        ("🇹🇼 台湾节点", r"tw|台湾"),
        ("🇺🇸 美国节点", r"us|美国"),
        ("🇰🇷 韩国节点", r"kr|韩国"),
        ("🇯🇵 日本节点", r"jp|日本"),
        ("🇸🇬 新加坡节点", r"sg|新加坡"),
        ("🇩🇪 德国节点", r"de|德国"),
        ("🇬🇧 英国节点", r"gb|uk|英国"),
        ("🇻🇳 越南节点", r"vn|越南"),
        ("🇱🇹 立陶宛节点", r"lt|立陶宛")

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
                "立陶宛": "🇱🇹 立陶宛节点"

            }

            return mapping.get(
                r.get("country", ""),
                "🧿 其它地区"
            )

    except:

        pass

    return "🧿 其它地区"

# =========================
# VMESS
# =========================
def parse_vmess(link):

    try:

        raw = link[8:]

        raw = raw.split("#")[0]

        data = safe_dec(raw)

        if not data:

            return None

        # 双层base64修复
        try:

            cfg = json.loads(data)

        except:

            data = safe_dec(data)

            cfg = json.loads(data)

        network = cfg.get("net", "tcp")

        proxy = {

            "label": get_final_label(
                cfg.get("add"),
                cfg.get("ps", "")
            ),

            "type": "vmess",

            "server": cfg.get("add"),

            "port": int(cfg.get("port", 443)),

            "uuid": cfg.get("id"),

            "alterId": int(
                cfg.get(
                    "aid",
                    cfg.get("alterId", 0)
                )
            ),

            "cipher": cfg.get(
                "scy",
                "auto"
            ),

            "udp": True,

            "tls": str(
                cfg.get("tls", "")
            ).lower() in [
                "tls",
                "true",
                "1"
            ],

            "network": network
        }

        # ws
        if network == "ws":

            proxy["ws-opts"] = {

                "path": cfg.get("path", "/"),

                "headers": {
                    "Host": cfg.get("host", "")
                }
            }

        # grpc
        elif network == "grpc":

            proxy["grpc-opts"] = {
                "grpc-service-name": cfg.get("path", "")
            }

        # h2
        elif network == "h2":

            proxy["h2-opts"] = {
                "host": [cfg.get("host", "")],
                "path": cfg.get("path", "/")
            }

        return proxy

    except Exception as e:

        print("VMESS失败:", e)

        return None

# =========================
# VLESS
# =========================
def parse_vless(link):

    try:

        u = urlparse(link)

        q = parse_qs(u.query)

        network = q.get("type", ["tcp"])[0]

        proxy = {

            "label": get_final_label(
                u.hostname,
                u.fragment
            ),

            "type": "vless",

            "server": u.hostname,

            "port": int(u.port or 443),

            "uuid": u.username,

            "cipher": "auto",

            "udp": True,

            "tls": (
                q.get("security", ["tls"])[0]
                != "none"
            ),

            "servername": (
                q.get("sni", [u.hostname])[0]
            ),

            "network": network
        }

        if network == "ws":

            proxy["ws-opts"] = {

                "path": (
                    q.get("path", ["/"])[0]
                ),

                "headers": {
                    "Host": (
                        q.get("host", [""])[0]
                    )
                }
            }

        elif network == "grpc":

            proxy["grpc-opts"] = {
                "grpc-service-name": (
                    q.get("serviceName", [""])[0]
                )
            }

        return proxy

    except Exception as e:

        print("VLESS失败:", e)

        return None

# =========================
# TROJAN
# =========================
def parse_trojan(link):

    try:

        u = urlparse(link)

        q = parse_qs(u.query)

        return {

            "label": get_final_label(
                u.hostname,
                u.fragment
            ),

            "type": "trojan",

            "server": u.hostname,

            "port": int(u.port or 443),

            "password": u.username,

            "sni": (
                q.get("sni", [u.hostname])[0]
            ),

            "udp": True
        }

    except Exception as e:

        print("TROJAN失败:", e)

        return None

# =========================
# SS
# =========================
def parse_ss(link):

    try:

        body = link[5:]

        remark = "SS"

        if "#" in body:

            body, remark = body.split("#", 1)

        if "@" not in body:

            dec = safe_dec(body)

            userinfo, serverinfo = dec.rsplit("@", 1)

        else:

            userinfo, serverinfo = body.split("@", 1)

            userinfo = safe_dec(userinfo)

        cipher, password = userinfo.split(":", 1)

        host, port = serverinfo.split(":")

        return {

            "label": get_final_label(
                host,
                remark
            ),

            "type": "ss",

            "server": host,

            "port": int(port),

            "cipher": cipher,

            "password": password,

            "udp": True
        }

    except Exception as e:

        print("SS失败:", e)

        return None

# =========================
# 主解析
# =========================
def parse_link(link):

    link = link.strip()

    if link.startswith("vmess://"):

        return parse_vmess(link)

    elif link.startswith("vless://"):

        return parse_vless(link)

    elif link.startswith("trojan://"):

        return parse_trojan(link)

    elif link.startswith("ss://"):

        return parse_ss(link)

    return None

# =========================
# 主程序
# =========================
def main():

    if not os.path.exists("nodes.txt"):

        print("❌ 缺少 nodes.txt")

        return

    with open(
        "nodes.txt",
        "r",
        encoding="utf-8"
    ) as f:

        urls = [
            x.strip()
            for x in f
            if x.strip()
        ]

    headers = {
        "User-Agent": "Clash.Meta"
    }

    all_text = ""

    # 下载订阅
    for url in urls:

        try:

            print("📥 下载:", url[:70])

            r = requests.get(
                url,
                timeout=20,
                headers=headers
            )

            txt = r.text.strip()

            # 尝试base64订阅
            dec = safe_dec(txt)

            if dec:

                txt = dec

            all_text += "\n" + txt

        except Exception as e:

            print("下载失败:", e)

    content = all_text.replace("\r", "")

    # =========================
    # 修复 vmess 丢失
    # =========================

    links = []

    # vmess单独抓
    vmess_links = re.findall(
        r'vmess://[A-Za-z0-9+/=_-]+',
        content
    )

    links.extend(vmess_links)

    # 其它协议
    other_links = re.findall(
        r'(?:vless|trojan|ss|hy2|hysteria2)://[^\s]+',
        content
    )

    links.extend(other_links)

    # 去重
    links = list(dict.fromkeys(links))

    print("📦 总链接:", len(links))

    proxies = []

    region_map = {}

    for link in links:

        p = parse_link(link)

        if not p:

            continue

        label = p.pop("label")

        if label not in region_map:

            region_map[label] = []

        idx = len(region_map[label]) + 1

        p["name"] = f"{label} @zmxooo {idx:02d}"

        region_map[label].append(
            p["name"]
        )

        proxies.append(p)

    if not proxies:

        print("❌ 没解析到节点")

        return

    regs = [

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

    for r in regs:

        groups.append({

            "name": r,

            "type": "url-test",

            "url": "http://www.gstatic.com/generate_204",

            "interval": 300,

            "tolerance": 50,

            "proxies": region_map.get(
                r,
                ["DIRECT"]
            )
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

            "enhanced-mode": "fake-ip",

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
                ] + regs
            },

            {

                "name": "⚡ 自动选择",

                "type": "url-test",

                "url": "http://www.gstatic.com/generate_204",

                "interval": 300,

                "proxies": [
                    p["name"]
                    for p in proxies
                ]
            }

        ] + groups,

        "rules": [

            "DOMAIN-SUFFIX,openai.com,🇺🇸 美国节点",

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

    print("✅ 完成")
    print("✅ 实际节点:", len(proxies))

if __name__ == "__main__":

    main()
