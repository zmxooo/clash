import base64
import json
import yaml
import os
import re
import requests
import gzip
import brotli

from urllib.parse import urlparse, parse_qs, unquote

# =====================================
# Base64 安全解码
# =====================================

def safe_dec(s):

    try:

        s = s.strip()

        s = s.replace("-", "+")
        s = s.replace("_", "/")

        s += "=" * (-len(s) % 4)

        return base64.b64decode(s).decode(
            "utf-8",
            errors="ignore"
        )

    except:

        return ""


# =====================================
# 节点地区
# =====================================

def get_final_label(server, remarks=""):

    text = unquote(str(remarks)).lower()

    rules = [

        ("🇭🇰 香港节点", r"hk|香港"),
        ("🇹🇼 台湾节点", r"tw|台湾"),
        ("🇺🇸 美国节点", r"us|美国"),
        ("🇯🇵 日本节点", r"jp|日本"),
        ("🇸🇬 新加坡节点", r"sg|新加坡"),
        ("🇰🇷 韩国节点", r"kr|韩国"),
        ("🇩🇪 德国节点", r"de|德国"),
        ("🇬🇧 英国节点", r"uk|英国"),
    ]

    for label, pattern in rules:

        if re.search(pattern, text):

            return label

    return "🧿 其它地区"


# =====================================
# VMESS
# =====================================

def parse_vmess(link):

    try:

        raw = link.replace("vmess://", "")

        raw = raw.split("#")[0]

        data = safe_dec(raw)

        if not data:
            return None

        # 双层 Base64
        if not data.strip().startswith("{"):

            data2 = safe_dec(data)

            if data2:
                data = data2

        cfg = json.loads(data)

        node = {

            "name": cfg.get("ps", "vmess"),

            "type": "vmess",

            "server": cfg["add"],

            "port": int(cfg["port"]),

            "uuid": cfg["id"],

            "alterId": int(cfg.get("aid", 0)),

            "cipher": cfg.get("scy", "auto"),

            "udp": True,

            "skip-cert-verify": True,
        }

        # TLS
        if str(cfg.get("tls")).lower() in ["tls", "true", "1"]:

            node["tls"] = True

        # network
        net = cfg.get("net")

        if net:
            node["network"] = net

        # ws
        if net == "ws":

            node["ws-opts"] = {

                "path": cfg.get("path", "/"),

                "headers": {
                    "Host": cfg.get("host", "")
                }
            }

        return node

    except:

        return None


# =====================================
# VLESS / TROJAN
# =====================================

def parse_vless_or_trojan(link):

    try:

        u = urlparse(link)

        q = parse_qs(u.query)

        is_vless = link.startswith("vless://")

        node = {

            "name": unquote(u.fragment) or u.hostname,

            "type": "vless" if is_vless else "trojan",

            "server": u.hostname,

            "port": int(u.port or 443),

            "udp": True,

            "skip-cert-verify": True,
        }

        if is_vless:

            node["uuid"] = u.username

            node["cipher"] = "auto"

        else:

            node["password"] = u.username

        if "security=tls" in link or "type=ws" in link:

            node["tls"] = True

        sni = q.get("sni")

        if sni:

            node["servername"] = sni[0]

        return node

    except:

        return None


# =====================================
# SS
# =====================================

def parse_ss(link):

    try:

        body = link[5:]

        if "#" in body:
            body = body.split("#")[0]

        if "@" not in body:

            body = safe_dec(body)

        userinfo, server = body.split("@", 1)

        if ":" not in userinfo:

            userinfo = safe_dec(userinfo)

        method, password = userinfo.split(":", 1)

        host, port = server.rsplit(":", 1)

        return {

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


# =====================================
# 通用解析
# =====================================

def parse_link(link):

    if link.startswith("vmess://"):

        return parse_vmess(link)

    elif link.startswith("vless://"):

        return parse_vless_or_trojan(link)

    elif link.startswith("trojan://"):

        return parse_vless_or_trojan(link)

    elif link.startswith("ss://"):

        return parse_ss(link)

    return None


# =====================================
# 获取订阅内容
# =====================================

def fetch(url):

    headers = {

        "User-Agent": "Clash.Meta",

        "Accept-Encoding": "gzip, deflate, br"
    }

    r = requests.get(
        url,
        timeout=20,
        headers=headers
    )

    raw = r.content

    # gzip
    try:
        raw = gzip.decompress(raw)
    except:
        pass

    # br
    try:
        raw = brotli.decompress(raw)
    except:
        pass

    txt = raw.decode(
        "utf-8",
        errors="ignore"
    )

    return txt


# =====================================
# 主程序
# =====================================

def main():

    if not os.path.exists("nodes.txt"):

        print("缺少 nodes.txt")

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

    for url in urls:

        try:

            print(f"抓取: {url}")

            txt = fetch(url)

            # HTML 页面过滤
            if "<html" in txt.lower():

                print("返回 HTML 页面")
                continue

            txt = txt.replace(
                "\r",
                "\n"
            )

            # Base64订阅判断
            if "vmess://" not in txt:

                dec = safe_dec(txt)

                if dec and (
                    "vmess://" in dec
                    or "vless://" in dec
                    or "trojan://" in dec
                ):
                    txt = dec

            # clash yaml
            try:

                y = yaml.safe_load(txt)

                if (
                    isinstance(y, dict)
                    and "proxies" in y
                ):

                    for p in y["proxies"]:

                        proxies.append(p)

                    continue

            except:
                pass

            # 提取
            patterns = [

                r'vmess://[^\s]+',

                r'vless://[^\s]+',

                r'trojan://[^\s]+',

                r'ss://[^\s]+'
            ]

            links = []

            for p in patterns:

                links.extend(
                    re.findall(p, txt)
                )

            # 去重
            links = list(set(links))

            for l in links:

                node = parse_link(l)

                if node:

                    proxies.append(node)

        except Exception as e:

            print(e)

    print(f"\n节点数量: {len(proxies)}")

    config = {

        "mixed-port": 7890,

        "allow-lan": True,

        "mode": "rule",

        "log-level": "info",

        "ipv6": False,

        "tun": {
            "enable": True,
            "stack": "mixed",
            "auto-route": True
        },

        "proxies": proxies,

        "proxy-groups": [

            {
                "name": "🚀 节点选择",

                "type": "select",

                "proxies": [
                    p["name"]
                    for p in proxies
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

    print("完成")


if __name__ == "__main__":

    main()
