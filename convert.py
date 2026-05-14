import base64, json, yaml, urllib.parse, os, re, requests, time

# 1. 核心识别：IP 归属地查询 + 备注匹配
def get_final_label(server, remarks):
    text = urllib.parse.unquote(remarks).lower().strip()
    meta = [
        ("🇭🇰 香港", r"hk|香港|hongkong|🇭🇰"), ("🇹🇼 台湾", r"tw|台湾|台灣|taiwan|🇹🇼"),
        ("🇺🇸 美国", r"us|美国|美國|america|usa|🇺🇸"), ("🇰🇷 韩国", r"kr|韩国|韓國|korea|🇰🇷"),
        ("🇯🇵 日本", r"jp|日本|japan|🇯🇵"), ("🇸🇬 新加坡", r"sg|新加坡|singapore|🇸🇬"),
        ("🇩🇪 德国", r"de|德国|德國|germany|ger|🇩🇪"), ("🇬🇧 英国", r"gb|uk|英国|英國|united kingdom|🇬🇧"),
        ("🇻🇳 越南", r"vn|越南|vietnam|🇻🇳"), ("🇱🇹 立陶宛", r"lt|立陶宛|lithuania")
    ]
    for label, pattern in meta:
        if re.search(pattern, text): return label
    
    # 尝试通过 IP 查询位置
    try:
        r = requests.get(f"http://ip-api.com{server}?lang=zh-CN", timeout=2).json()
        if r.get("status") == "success":
            c = r.get("country")
            country_map = {"中国": "🇨🇳 中国", "香港": "🇭🇰 香港", "台湾": "🇹🇼 台湾", "美国": "🇺🇸 美国", "日本": "🇯🇵 日本", "韩国": "🇰🇷 韩国", "新加坡": "🇸🇬 新加坡", "德国": "🇩🇪 德国", "英国": "🇬🇧 英国", "越南": "🇻🇳 越南", "立陶宛": "🇱🇹 立陶宛"}
            return country_map.get(c, f"🌍 {c}")
    except: pass
    return "🌍 其他"

# 2. 全量解析器（严谨校验版：5大协议独立入口，互不干扰）
def parse_link(link):
    try:
        # 去掉可能的重复前缀
        link = link.replace('vmess://vmess://', 'vmess://').strip()
        
        # --- [协议 1]: VMess ---
        if link.startswith('vmess://'):
            # 去掉 # 后缀，只取 Base64 部分
            b64_part = link[8:].split('#')[0].split('?')[0]
            b64_part += '=' * (-len(b64_part) % 4)
            d = json.loads(base64.b64decode(b64_part).decode('utf-8'))
            return {
                "label": get_final_label(d.get("add"), d.get("ps")), 
                "type": "vmess", "server": d.get("add"), "port": int(d.get("port")), 
                "uuid": d.get("id"), "alterId": 0, "cipher": "auto", 
                "tls": d.get("tls") in ["tls", True, 1, "1"], "skip-cert-verify": True
            }

        # --- [协议 2]: Shadowsocks (SS) ---
        if link.startswith('ss://'):
            u = urllib.parse.urlparse(link)
            server_part = u.netloc.split("@")[-1]
            host = server_part.split(":")[0]
            port = int(server_part.split(":")[1]) if ":" in server_part else 443
            method, password = "aes-256-gcm", "password"
            if "@" in u.netloc:
                userinfo_b64 = u.netloc.split("@")[0]
                userinfo_b64 += '=' * (-len(userinfo_b64) % 4)
                userinfo = base64.b64decode(userinfo_b64).decode('utf-8').split(":")
                method, password = userinfo[0], userinfo[1]
            return {"label": get_final_label(host, u.fragment), "type": "ss", "server": host, "port": port, "cipher": method, "password": password, "udp": True}

        # --- [协议 3]: VLESS ---
        if link.startswith('vless://'):
            u = urllib.parse.urlparse(link)
            q = urllib.parse.parse_qs(u.query)
            sni = q.get("sni", [""]) or q.get("host", [""]) or [u.hostname]
            return {"label": get_final_label(u.hostname, u.fragment), "type": "vless", "server": u.hostname, "port": int(u.port), "uuid": u.username, "cipher": "auto", "tls": True, "sni": str(sni[0]), "skip-cert-verify": True, "udp": True}

        # --- [协议 4]: Trojan ---
        if link.startswith('trojan://'):
            u = urllib.parse.urlparse(link)
            q = urllib.parse.parse_qs(u.query)
            sni = q.get("sni", [""]) or q.get("host", [""]) or [u.hostname]
            return {"label": get_final_label(u.hostname, u.fragment), "type": "trojan", "server": u.hostname, "port": int(u.port), "password": u.username, "tls": True, "sni": str(sni[0]), "skip-cert-verify": True, "udp": True}

        # --- [协议 5]: Hysteria2 ---
        if any(link.startswith(p) for p in ['hysteria2://', 'hy2://']):
            u = urllib.parse.urlparse(link)
            return {"label": get_final_label(u.hostname, u.fragment), "type": "hysteria2", "server": u.hostname, "port": int(u.port) if u.port else 443, "password": u.username, "auth": u.username, "sni": u.hostname, "skip-cert-verify": True}

    except Exception as e:
        print(f"解析出错: {link[:20]}... -> {e}")
        return None

def main():
    if not os.path.exists('nodes.txt'): return
    with open('nodes.txt', 'r', encoding='utf-8') as f:
        ls = f.read().splitlines()
    
    pxs, name_count, valid_links = [], {}, []
    channel_mark = "@zmxooo"
    
    for l in ls:
        l = l.strip()
        if not l or any(l.startswith(s) for s in ['import', 'def', 'git']): continue
        p = parse_link(l)
        if p:
            valid_links.append(l)
            base_label = p.pop('label')
            name_count[base_label] = name_count.get(base_label, 0) + 1
            p['name'] = f"{base_label} {channel_mark} {name_count[base_label]:02d}"
            pxs.append(p)
            time.sleep(0.05)

    if not pxs: return

    # 动态抓取国家前缀
    group_labels = sorted(list(set([p['name'].split(' @')[0] for p in pxs if ' @' in p['name']])))
    
    ags = [
        {"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择", "DIRECT"] + group_labels},
        {"name": "⚡ 自动选择", "type": "url-test", "url": "http://gstatic.com", "interval": 300, "proxies": [p['name'] for p in pxs]}
    ]
    
    for r in group_labels:
        ags.append({
            "name": r, "type": "url-test", "url": "http://gstatic.com", 
            "interval": 300, "proxies": [p['name'] for p in pxs if p['name'].startswith(r)]
        })
    
    cf = {"port": 7890, "proxies": pxs, "proxy-groups": ags, "rules": ["MATCH,🚀 节点选择"]}
    with open('config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(cf, f, allow_unicode=True, sort_keys=False)
    
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(base64.b64encode("\n".join(valid_links).encode('utf-8')).decode('utf-8'))

if __name__ == "__main__":
    main()
