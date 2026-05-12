import base64
import json
import yaml
import os
import re
import requests
from urllib.parse import urlparse, parse_qs, unquote

def safe_dec(d):
    try:
        d = d.strip().replace('-', '+').replace('_', '/')
        return base64.b64decode(
            d + '=' * (-len(d) % 4)
        ).decode('utf-8', 'ignore')
    except:
        return ""

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

def parse_link(link):

    try:

        link = link.strip()

        # VMESS
        if link.startswith("vmess://"):

            raw = link[8:].split('#')[0]

            cfg = json.loads(safe_dec(raw))

            return {
                "label": get_final_label(
                    cfg.get("add"),
                    cfg.get("ps", "")
                ),

                "name": cfg.get("ps", "VMESS"),

                "type": "vmess",
                "server": cfg.get("add"),
                "port": int(cfg.get("port", 443)),
                "uuid": cfg.get("id"),
                "alterId": int(cfg.get("aid", 0)),
                "cipher": cfg.get("scy", "auto"),

                "tls": str(
                    cfg.get("tls", "")
                ).lower() in ["tls", "true", "1"],

                "network": cfg.get("net", "tcp"),

                "udp": True
            }

        # VLESS
        elif link.startswith("vless://"):

            u = urlparse(link)

            q = parse_qs(u.query)

            return {
                "label": get_final_label(
                    u.hostname,
                    u.fragment
                ),

                "name": unquote(u.fragment)
                or "VLESS",

                "type": "vless",
                "server": u.hostname,
                "port": int(u.port or 443),
                "uuid": u.username,
                "cipher": "auto",

                "tls": True,

                "servername": (
                    q.get("sni")
                    or [u.hostname]
                )[0],

                "network": (
                    q.get("type")
                    or ["tcp"]
                )[0],

                "udp": True
            }

        # TROJAN
        elif link.startswith("trojan://"):

            u = urlparse(link)

            q = parse_qs(u.query)

            return {
                "label": get_final_label(
                    u.hostname,
                    u.fragment
                ),

                "name": unquote(u.fragment)
                or "TROJAN",

                "type": "trojan",
                "server": u.hostname,
                "port": int(u.port or 443),
                "password": u.username,

                "sni": (
                    q.get("sni")
                    or [u.hostname]
                )[0],

                "udp": True
            }

        # SS
        elif link.startswith("ss://"):

            body = link[5:]

            if "#" in body:
                body, remark = body.split("#", 1)
            else:
                remark = "SS"

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

                "name": unquote(remark),

                "type": "ss",
                "server": host,
                "port": int(port),
                "cipher": cipher,
                "password": password,
                "udp": True
            }

    except Exception as e:

        print("解析失败:", link[:80], e)

    return None

def main():

    if not os.path.exists("nodes.txt"):

        print("缺少 nodes.txt")

        return

    all_text = ""

    with open(
        "nodes.txt",
        "r",
        encoding="utf-8"
    ) as f:

        urls = [x.strip() for x in f if x.strip()]

    headers = {
        "User-Agent": "Clash.Meta"
    }

    for url in urls:

        try:

            print("下载订阅:", url[:60])

            r = requests.get(
                url,
                timeout=20,
                headers=headers
            )

            txt = r.text.strip()

            # base64订阅
            dec = safe_dec(txt)

            if dec:
                txt = dec

            all_text += "\n" + txt

        except Exception as e:

            print("失败:", e)

    content = all_text.replace('\r', '')

    # 修复vmess匹配
    links = re.findall(
        r'(?:vmess|vless|trojan|ss|hy2|hysteria2)://[^\n\r ]+',
        content
    )

    print("发现节点:", len(links))

    proxies = []

    region_map = {}

    for link in links:

        p = parse_link(link)

        if p:

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

        print("没有解析到节点")

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

    print("完成")
    print("节点总数:", len(proxies))

if __name__ == "__main__":
    main()
