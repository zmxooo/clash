import base64, json, yaml, urllib.parse, os, re, requests, time

# 1. 核心识别：IP 归属地查询 + 备注匹配
def get_final_label(server, remarks):
    text = urllib.parse.unquote(remarks).lower().strip()
    meta = [
        ("🇭🇰 香港节点", r"hk|香港|hongkong|🇭🇰"), ("🇹🇼 台湾节点", r"tw|台湾|台灣|taiwan|🇹🇼"),
        ("🇺🇸 美国节点", r"us|美国|美國|america|usa|🇺🇸"), ("🇰🇷 韩国节点", r"kr|韩国|韓國|korea|🇰🇷"),
        ("🇯🇵 日本节点", r"jp|日本|japan|🇯🇵"), ("🇸🇬 新加坡节点", r"sg|新加坡|singapore|🇸🇬"),
        ("🇩🇪 德国节点", r"de|德国|德國|germany|ger|🇩🇪"), ("🇬🇧 英国节点", r"gb|uk|英国|英國|united kingdom|🇬🇧"),
        ("🇻🇳 越南节点", r"vn|越南|vietnam|🇻🇳"), ("🇱🇹 立陶宛节点", r"lt|立陶宛|lithuania")
    ]
    for label, pattern in meta:
        if re.search(pattern, text): return label
    try:
        r = requests.get(f"http://ip-api.com{server}?lang=zh-CN", timeout=2).json()
        if r.get("status") == "success":
            c = r.get("country")
            m = {"中国": "🇨🇳 中国", "香港": "🇭🇰 香港节点", "台湾": "🇹🇼 台湾节点", "美国": "🇺🇸 美国节点", "日本": "🇯🇵 日本节点", "韩国": "🇰🇷 韩国节点", "新加坡": "🇸🇬 新加坡节点", "德国": "🇩🇪 德国节点", "英国": "🇬🇧 英国节点", "越南": "🇻🇳 越南节点", "立陶宛": "🇱🇹 立陶宛节点"}
            return m.get(c, f"🌍 {c}")
    except: pass
    return "🧿 其它地区"

# 2. 全量解析器：修复 vm 端口、ss 格式及 hy2 入口
def parse_link(link):
    try:
        link = link.replace('vmess://vmess://', 'vmess://').strip()
        u = urllib.parse.urlparse(link)
        
        # --- VMess ---
        if link.startswith('vmess://'):
            b64_data = link[8:].split('#')[0].split('?')[0]
            b64_data += '=' * (-len(b64_data) % 4)
            d = json.loads(base64.b64decode(b64_data).decode('utf-8'))
            return {"label": get_final_label(d.get("add"), d.get("ps")), "type": "vmess", "server": d.get("add"), "port": int(d.get("port")), "uuid": d.get("id"), "alterId": 0, "cipher": "auto", "tls": d.get("tls") in ["tls", True, 1], "skip-cert-verify": True, "udp": True}

        # --- VLESS / Trojan ---
        elif link.startswith('vless://') or link.startswith('trojan://'):
            q = urllib.parse.parse_qs(u.query)
            p_type = "vless" if link.startswith('vless://') else "trojan"
            sni = q.get("sni", [""]) or q.get("host", [""]) or [u.hostname]
            p = {"label": get_final_label(u.hostname, u.fragment), "type": p_type, "server": u.hostname, "port": int(u.port), "tls": True, "sni": str(sni[0]), "skip-cert-verify": True, "udp": True}
            if p_type == "vless": p.update({"uuid": u.username, "cipher": "auto"})
            else: p["password"] = u.username
            return p

        # --- Shadowsocks (SS) ---
        elif link.startswith('ss://'):
            server_part = u.netloc.split("@")[-1]
            host = server_part.split(":")[0]
            port = int(server_part.split(":")[1]) if ":" in server_part else 443
            method, password = "aes-256-gcm", "password"
            if "@" in u.netloc:
                user_b64 = u.netloc.split("@")[0]
                user_b64 += '=' * (-len(user_b64) % 4)
                userinfo = base64.b64decode(user_b64).decode('utf-8').split(":")
                if len(userinfo) > 1: method, password = userinfo[0], userinfo[1]
            return {"label": get_final_label(host, u.fragment), "type": "ss", "server": host, "port": port, "cipher": method, "password": password, "udp": True}

        # --- Hysteria2 ---
        elif any(link.startswith(p) for p in ['hysteria2://', 'hy2://']):
            return {"label": get_final_label(u.hostname, u.fragment), "type": "hysteria2", "server": u.hostname, "port": int(u.port) if u.port else 443, "password": u.username, "auth": u.username, "sni": u.hostname, "skip-cert-verify": True, "udp": True}
            
    except: return None

def main():
    if not os.path.exists('nodes.txt'): return
    with open('nodes.txt', 'r', encoding='utf-8') as f:
        ls = f.read().splitlines()
    
    pxs, valid_links, region_map = [], [], {}
    channel_mark = "@zmxooo"
    
    for l in ls:
        l = l.strip()
        if not l or any(l.startswith(s) for s in ['import', 'def', 'git']): continue
        p = parse_link(l)
        if p:
            valid_links.append(l)
            label = p.pop('label')
            idx = len(region_map.get(label, [])) + 1
            p['name'] = f"{label} {channel_mark} {idx:02d}"
            pxs.append(p)
            region_map.setdefault(label, []).append(p['name'])
            time.sleep(0.05)

    if not pxs: return

    # --- 策略组布局 ---
    target_regions = ["🇭🇰 香港节点", "🇹🇼 台湾节点", "🇯🇵 日本节点", "🇸🇬 新加坡节点", "🇰🇷 韩国节点", "🇺🇸 美国节点", "🇩🇪 德国节点", "🇬🇧 英国节点", "🧿 其它地区"]
    region_groups = [{"name": r, "type": "url-test", "url": "http://gstatic.com", "interval": 300, "proxies": region_map.get(r, ["Direct"])} for r in target_regions]

    all_nodes = [p['name'] for p in pxs]
    
    cf = {
        "mixed-port": 7890, "allow-lan": True, "mode": "rule", "log-level": "info",
        "tun": {"enable": True, "stack": "mixed", "auto-route": True, "auto-detect-interface": True},
        "dns": {"enable": True, "enhanced-mode": "fake-ip", "nameserver": ["119.29.29.29", "223.5.5.5"]},
        "proxies": pxs + [{"name": "Direct", "type": "direct"}],
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择", "☢ 负载均衡-散列"] + target_regions + ["Direct"], "icon": "https://githubusercontent.com"},
            {"name": "⚡ 自动选择", "type": "url-test", "url": "http://gstatic.com", "interval": 300, "proxies": all_nodes, "icon": "https://githubusercontent.com"},
            {"name": "☢ 负载均衡-散列", "type": "load-balance", "strategy": "consistent-hashing", "url": "http://gstatic.com", "interval": 300, "proxies": all_nodes, "icon": "https://githubusercontent.com"},
            {"name": "📹 YouTube", "type": "select", "proxies": ["🚀 节点选择"] + target_regions, "icon": "https://githubusercontent.com"},
            {"name": "📲 Telegram", "type": "select", "proxies": ["🚀 节点选择", "🇸🇬 新加坡节点"], "icon": "https://githubusercontent.com"},
            {"name": "🤖 AI", "type": "select", "proxies": ["🇺🇸 美国节点", "🇯🇵 日本节点", "🇸🇬 新加坡节点"], "icon": "https://githubusercontent.com"},
            {"name": "📹 哔哩哔哩", "type": "select", "proxies": ["Direct", "🇭🇰 香港节点", "🇹🇼 台湾节点"], "icon": "https://githubusercontent.com"},
            {"name": "🎥 Netflix", "type": "select", "proxies": ["🚀 节点选择", "⚡ 自动选择"], "icon": "https://githubusercontent.com"}
        ] + region_groups,
        "rules": [
            "DOMAIN-SUFFIX,youtube.com,📹 YouTube", "DOMAIN-SUFFIX,googlevideo.com,📹 YouTube",
            "DOMAIN-SUFFIX,telegram.org,📲 Telegram", "DOMAIN-KEYWORD,telegram,📲 Telegram",
            "DOMAIN-KEYWORD,openai,🤖 AI", "DOMAIN-SUFFIX,chatgpt.com,🤖 AI",
            "DOMAIN-SUFFIX,bilibili.com,📹 哔哩哔哩", "DOMAIN-SUFFIX,netflix.com,🎥 Netflix",
            "GEOIP,CN,Direct", "MATCH,🚀 节点选择"
        ]
    }

    with open('config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(cf, f, allow_unicode=True, sort_keys=False)
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(base64.b64encode("\n".join(valid_links).encode('utf-8')).decode('utf-8'))

if __name__ == "__main__":
    main()
