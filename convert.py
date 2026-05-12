import base64, json, yaml, urllib.parse, os, re, requests, time

# 1. 核心定位逻辑 (保持之前的 IP 纠偏功能)
def get_final_label(server, remarks):
    text = urllib.parse.unquote(remarks).lower().strip()
    meta = [
        ("🇭🇰香港节点", r"hk|香港|hongkong|🇭🇰"), ("🇨🇳台湾节点", r"tw|台湾|台灣|taiwan|🇹🇼"),
        ("🇺🇲美国节点", r"us|美国|美國|america|usa|🇺🇸"), ("🇰🇷韩国节点", r"kr|韩国|韓國|korea|🇰🇷"),
        ("🇯🇵日本节点", r"jp|日本|japan|🇯🇵"), ("🇸🇬新加坡节点", r"sg|新加坡|singapore|🇸🇬"),
        ("🇩🇪德国节点", r"de|德国|德國|germany|ger|🇩🇪"), ("🇬🇧英国节点", r"gb|uk|英国|英國|united kingdom|🇬🇧"),
        ("🇻🇳越南节点", r"vn|越南|vietnam|🇻🇳"), ("🇱🇹立陶宛节点", r"lt|立陶宛|lithuania")
    ]
    for label, pattern in meta:
        if re.search(pattern, text): return label
    try:
        r = requests.get(f"http://ip-api.com{server}?lang=zh-CN", timeout=2).json()
        if r.get("status") == "success":
            c = r.get("country")
            m = {"中国": "🇨🇳 中国", "香港": "🇭🇰香港节点", "台湾": "🇨🇳台湾节点", "美国": "🇺🇲美国节点", "日本": "🇯🇵日本节点", "韩国": "🇰🇷韩国节点", "新加坡": "🇸🇬新加坡节点", "德国": "🇩🇪德国节点", "英国": "🇬🇧英国节点", "越南": "🇻🇳越南节点", "立陶宛": "🇱🇹立陶宛节点"}
            return m.get(c, f"🧿其它地区")
    except: pass
    return "🧿其它地区"

# 2. 全协议解析器 (严谨版)
def parse_link(link):
    try:
        link = link.replace('vmess://vmess://', 'vmess://').strip()
        if link.startswith('vmess://'):
            b64 = link[8:].split('#')[0].split('?')[0]
            b64 += '=' * (-len(b64) % 4)
            d = json.loads(base64.b64decode(b64).decode('utf-8'))
            return {"label": get_final_label(d.get("add"), d.get("ps")), "type": "vmess", "server": d.get("add"), "port": int(d.get("port")), "uuid": d.get("id"), "alterId": 0, "cipher": "auto", "tls": d.get("tls") in ["tls", True, 1], "skip-cert-verify": True, "udp": True}
        u = urllib.parse.urlparse(link)
        if any(link.startswith(p) for p in ['vless://', 'trojan://']):
            q = urllib.parse.parse_qs(u.query)
            sni = q.get("sni", [""])[0] or q.get("host", [""])[0] or u.hostname
            p = {"label": get_final_label(u.hostname, u.fragment), "type": "vless" if "vless" in link else "trojan", "server": u.hostname, "port": int(u.port), "tls": True, "sni": str(sni), "skip-cert-verify": True, "udp": True}
            if "vless" in link: p.update({"uuid": u.username, "cipher": "auto"})
            else: p["password"] = u.username
            return p
        elif link.startswith('ss://'):
            server_part = u.netloc.split("@")[-1]
            host, port = server_part.split(":") if ":" in server_part else (server_part, "443")
            return {"label": get_final_label(host, u.fragment), "type": "ss", "server": host, "port": int(port), "cipher": "aes-256-gcm", "password": u.username if "@" in u.netloc else "password", "udp": True}
        elif any(link.startswith(p) for p in ['hy2://', 'hysteria2://']):
            return {"label": get_final_label(u.hostname, u.fragment), "type": "hysteria2", "server": u.hostname, "port": int(u.port) if u.port else 443, "password": u.username, "auth": u.username, "sni": u.hostname, "skip-cert-verify": True, "udp": True}
    except: return None

def main():
    if not os.path.exists('nodes.txt'): return
    with open('nodes.txt', 'r', encoding='utf-8') as f:
        ls = f.read().splitlines()
    pxs, valid_links = [], []
    region_map = {} # 存放各组节点名

    for l in ls:
        l = l.strip()
        if not l or any(l.startswith(s) for s in ['import', 'def', 'git']): continue
        p = parse_link(l)
        if p:
            valid_links.append(l)
            label = p.pop('label')
            idx = len(region_map.get(label, [])) + 1
            p['name'] = f"{label} @zmxooo {idx:02d}"
            pxs.append(p)
            region_map.setdefault(label, []).append(p['name'])
            time.sleep(0.05)

    if not pxs: return

    # --- 高级模版注入 ---
    # 定义所有需要的国家组
    target_regions = ["🇭🇰香港节点", "🇨🇳台湾节点", "🇯🇵日本节点", "🇸🇬新加坡节点", "🇰🇷韩国节点", "🇺🇲美国节点", "🇩🇪德国节点", "🇬🇧英国节点", "🧿其它地区"]
    
    # 填充每个组，如果没有节点则放入“DIRECT”占位防止报错
    groups_config = []
    for r in target_regions:
        proxies_in_r = region_map.get(r, [])
        groups_config.append({
            "name": r,
            "type": "url-test",
            "url": "http://gstatic.com",
            "interval": 300,
            "proxies": proxies_in_r if proxies_in_r else ["DIRECT"]
        })

    # 构建最终 YAML 结构
    final_config = {
        "mixed-port": 7890, "allow-lan": True, "mode": "rule", "log-level": "info", "ipv6": False,
        "global-ua": "clash.meta",
        "sniffer": {"enable": True, "sniff": {"HTTP": {"ports": [80, "8080-8880"], "override-destination": True}, "TLS": {"ports": [443, 8443]}, "QUIC": {"ports": [443, 8443]}}},
        "tun": {"enable": True, "stack": "mixed", "auto-route": True, "auto-detect-interface": True},
        "dns": {"enable": True, "listen": "0.0.0.0:53", "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16", "nameserver": ["https://doh.pub", "https://alidns.com"]},
        "proxies": pxs + [{"name": "🟢 直连", "type": "direct"}],
        "proxy-groups": [
            {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": ["♻️ 自动选择", "DIRECT"] + target_regions
            },
            {
                "name": "♻️ 自动选择",
                "type": "url-test",
                "url": "http://gstatic.com",
                "interval": 300,
                "proxies": [p['name'] for p in pxs]
            }
        ] + groups_config + [
            {"name": "📹 YouTube", "type": "select", "proxies": ["🚀 节点选择"] + target_regions},
            {"name": "📲 Telegram", "type": "select", "proxies": ["🚀 节点选择"] + target_regions},
            {"name": "🤖 AI", "type": "select", "proxies": ["🇺🇲美国节点", "🇯🇵日本节点", "🇸🇬新加坡节点", "🚀 节点选择"]},
            {"name": "🍀 Google", "type": "select", "proxies": ["🚀 节点选择", "DIRECT"]}
        ],
        "rules": [
            "DOMAIN-SUFFIX,youtube.com,📹 YouTube",
            "DOMAIN-SUFFIX,googlevideo.com,📹 YouTube",
            "DOMAIN-SUFFIX,telegram.org,📲 Telegram",
            "DOMAIN-KEYWORD,openai,🤖 AI",
            "DOMAIN-KEYWORD,google,🍀 Google",
            "MATCH,🚀 节点选择"
        ]
    }

    with open('config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(final_config, f, allow_unicode=True, sort_keys=False)
    
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(base64.b64encode("\n".join(valid_links).encode('utf-8')).decode('utf-8'))

if __name__ == "__main__":
    main()
