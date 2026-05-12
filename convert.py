import base64
import json
import yaml
import os
import re
import requests
from urllib.parse import urlparse, parse_qs, unquote

# =========================
# Base64 安全解码
# =========================
def safe_dec(data):
    try:
        data = data.strip()

        # URLSafe Base64 修复
        data = data.replace("-", "+")
        data = data.replace("_", "/")

        # 补齐 padding
        data += "=" * (-len(data) % 4)

        return base64.b64decode(data).decode(
            "utf-8",
            errors="ignore"
        )

    except:
        return ""


# =========================
# 节点地区识别
# =========================
def get_final_label(server, remarks=""):

    text = unquote(str(remarks)).lower()

    rules = [
        ("🇭🇰 香港节点", r"hk|香港|hongkong"),
        ("🇹🇼 台湾节点", r"tw|台湾|taiwan"),
        ("🇺🇸 美国节点", r"us|美国|usa"),
        ("🇯🇵 日本节点", r"jp|日本|japan"),
        ("🇸🇬 新加坡节点", r"sg|新加坡|singapore"),
        ("🇰🇷 韩国节点", r"kr|韩国|korea"),
        ("🇩🇪 德国节点", r"de|德国|germany"),
        ("🇬🇧 英国节点", r"uk|英国|england"),
    ]

    for label, pattern in rules:
        if re.search(pattern, text):
            return label

    return "🧿 其它地区"


# =========================
# VMESS 解析
# =========================
def parse_vmess(link):

    try:

        raw = link[8:].strip()

        # 第一层 Base64
        data = safe_dec(raw)

        # 有些机场是双层 Base64
        try:
            cfg = json.loads(data)

        except:
            data2 = safe_dec(data)
            cfg = json.loads(data2)

        server = cfg.get("add")

        return {
            "label": get_final_label(
                server,
                cfg.get("ps", "")
            ),

            "name": cfg.get("ps", "VMESS"),

            "type": "vmess",

            "server": server,

            "port": int(cfg.get("port", 443)),

            "uuid": cfg.get("id"),

            "alterId": int(cfg.get("aid", 0)),

            "cipher": cfg.get("scy", "auto"),

            "tls": str(
                cfg.get("tls", "")
            ).lower() in ["tls", "true", "1"],

            "network": cfg.get("net", "tcp"),

            "servername": cfg.get("sni", ""),

            "ws-opts": {
                "path": cfg.get("path", "/"),
                "headers": {
                    "Host": cfg.get("host", "")
                }
            },

            "udp": True,

            "skip-cert-verify": True
        }

    except Exception as e:
        return None


# =========================
# VLESS/TROJAN
# =========================
def parse_vless_or_trojan(link):

    try:

        u = urlparse(link)

        q = parse_qs(u.query)

        is_vless = link.startswith("vless://")

        p = {
            "label": get_final_label(
                u.hostname,
                u.fragment
            ),

            "name": unquote(u.fragment) or u.hostname,

            "type": "vless" if is_vless else "trojan",

            "server": u.hostname,

            "port": int(u.port or 443),

            "tls": True,

            "sni": q.get(
                "sni",
                [u.hostname]
            )[0],

            "udp": True,

            "skip-cert-verify": True
        }

        if is_vless:

            p["uuid"] = u.username
            p["cipher"] = "auto"

        else:

            p["password"] = u.username

        return p

    except:
        return None


# =========================
# SS
# =========================
def parse_ss(link):

    try:

        body = link[5:]

        if "#" in body:
            body = body.split("#")[0]

        if "@" not in body:

            body = safe_dec(body)

        if "@" in body:

            userinfo, server = body.split("@", 1)

            if ":" not in userinfo:

                userinfo = safe_dec(userinfo)

            method, password = userinfo.split(":", 1)

            host, port = server.rsplit(":", 1)

            return {
                "label": get_final_label(host),

                "name": host,

                "type": "ss",

                "server": host,

                "port": int(port),

                "cipher": method,

                "password": password,

                "udp": True
            }

    except:
        return None


# =========================
# 通用解析
# =========================
def parse_link(link):

    link = link.strip()

    if link.startswith("vmess://"):
        return parse_vmess(link)

    elif link.startswith("vless://"):
        return parse_vless_or_trojan(link)

    elif link.startswith("trojan://"):
        return parse_vless_or_trojan(link)

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

    proxies = []

    headers = {
        "User-Agent": "Clash.Meta",
        "Accept-Encoding": "gzip"
    }

    # =========================
    # 抓订阅
    # =========================
    for url in urls:

        try:

            print(f"📡 抓取: {url}")

            r = requests.get(
                url,
                timeout=20,
                headers=headers
            )

            txt = r.text

            txt = txt.replace(
                "\r",
                "\n"
            )

            # Base64 订阅
            dec = safe_dec(txt)

            if dec:
                txt = dec

            # Clash YAML
            try:

                y = yaml.safe_load(txt)

                if (
                    isinstance(y, dict)
                    and "proxies" in y
                ):

                    for p in y["proxies"]:

                        if "name" not in p:
                            continue

                        proxies.append(p)

                    continue

            except:
                pass

            # =========================
            # 正则提取
            # =========================

            patterns = [

                r'vmess://[A-Za-z0-9+/=_-]+',

                r'vless://[^\s]+',

                r'trojan://[^\s]+',

                r'ss://[A-Za-z0-9+/=_:@.?&%-]+'
            ]

            links = []

            for p in patterns:

                found = re.findall(
                    p,
                    txt
                )

                links.extend(found)

            # 去重
            links = list(set(links))

            # =========================
            # 解析
            # =========================
            for l in links:

                node = parse_link(l)

                if node:
                    proxies.append(node)

        except Exception as e:

            print(f"❌ 失败: {e}")

    # =========================
    # 去重
    # =========================
    final = []

    seen = set()

    for p in proxies:

        key = (
            p.get("server"),
            p.get("port"),
            p.get("type")
        )

        if key in seen:
            continue

        seen.add(key)

        final.append(p)

    print(f"\n✅ 最终节点数量: {len(final)}")

    # =========================
    # 配置生成
    # =========================
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

        "proxies": final,

        "proxy-groups": [

            {
                "name": "🚀 节点选择",

                "type": "select",

                "proxies": [
                    p["name"]
                    for p in final
                ]
            },

            {
                "name": "⚡ 自动选择",

                "type": "url-test",

                "url": "http://www.gstatic.com/generate_204",

                "interval": 300,

                "proxies": [
                    p["name"]
                    for p in final
                ]
            }
        ],

        "rules": [

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
