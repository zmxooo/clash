import base64, json, yaml, urllib.parse, os, re, requests, time

# 核心：根据 IP 归属地或备注识别国家
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
    try:
        r = requests.get(f"http://ip-api.com{server}?lang=zh-CN", timeout=2).json()
        if r.get("status") == "success":
            country = r.get("country")
            country_map = {"中国": "🇨🇳 中国", "香港": "🇭🇰 香港", "台湾": "🇹🇼 台湾", "美国": "🇺🇸 美国", "日本": "🇯🇵 日本", "韩国": "🇰🇷 韩国", "新加坡": "🇸🇬 新加坡", "德国": "🇩🇪 德国", "英国": "🇬🇧 英国", "越南": "🇻🇳 越南", "立陶宛": "🇱🇹 立陶宛"}
            return country_map.get(country, f"🌍 {country}")
    except: pass
    return "🌍 其他"

# 通用解析器：支持 VMess, VLESS, Trojan, SS, HY2
def parse_link(link):
    try:
        link = link.replace('vmess://vmess://', 'vmess://').strip()
        u = urllib.parse.urlparse(link)
        # VMess
        if link.startswith('vmess://'):
            b64 = link[8:].split('#')[0].split('?')[0]
            b64 += '=' * (-len(b64) % 4)
            d = json.loads(base64.b64decode(b64).decode('utf-8'))
            return {"label": get_final_label(d.get("add"), d.get("ps")), "type": "vmess", "server": d.get("add"), "port": int(d.get("port")), "uuid": d.get("id"), "alterId": 0, "cipher": "auto", "tls": d.get("tls") in ["tls", True, 1], "skip-cert-verify": True}
        # VLESS / Trojan
        elif any(link.startswith(p) for p in ['vless://', 'trojan://']):
            q = urllib.parse.parse_qs(u.query)
            p_type = "vless" if link.startswith('vless://') else "trojan"
            sni = (q.get("sni", [""]) or q.get("host", [""]) or [u.hostname])[0]
            p = {"label": get_final_label(u.hostname, u.fragment), "type": p_type, "server": u.hostname, "port": int(u.port), "tls": True, "sni": sni, "skip-cert-verify": True, "udp": True}
            if p_type == "vless": p.update({"uuid": u.username, "cipher": "auto"})
            else: p["password"] = u.username
            return p
        # SS
        elif link.startswith('ss://'):
            server_part = u.netloc.split("@")[-1]
            host, port = server_part.split(":") if ":" in server_part else (server_part, "443")
            return {"label": get_final_label(host, u.fragment), "type": "ss", "server": host, "port": int(port), "cipher": "aes-256-gcm", "password": u.username if "@" in u.netloc else "password", "udp": True}
        # HY2
        elif any(link.startswith(p) for p in ['hysteria2://', 'hy2://']):
            return {"label": get_final_label(u.hostname, u.fragment), "type": "hysteria2", "server": u.hostname, "port": int(u.port) if u.port else 443, "password": u.username, "auth": u.username, "sni": u.hostname, "skip-cert-verify": True}
    except: return None

def main():
    if not os.path.exists('nodes.txt'): return
    with open('nodes.txt', 'r', encoding='utf-8') as f:
        ls = f.read().splitlines()
    pxs, name_count, valid_links = [], {}, []
    for l in ls:
        l = l.strip()
        if not l or any(l.startswith(s) for s in ['import', 'def', 'git']): continue
        p = parse_link(l)
        if p:
            valid_links.append(l)
            base_label = p.pop('label')
            name_count[base_label] = name_count.get(base_label, 0) + 1
            p['name'] = f"{base_label} @zmxooo {name_count[base_label]:02d}"
            pxs.append(p)
            time.sleep(0.05)
    if not pxs: return
    # 自动分组
    found_regions = sorted(list(set([p['name'].rsplit(' ', 2)[0] for p in pxs if ' ' in p['name']])))
    ags = [{"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择", "DIRECT"] + found_regions}]
    ags.append({"name": "⚡ 自动选择", "type": "url-test", "url": "http://gstatic.com", "interval": 300, "proxies": [p['name'] for p in pxs]})
    for r in found_regions:
        ags.append({"name": r, "type": "url-test", "url": "http://gstatic.com", "interval": 300, "proxies": [p['name'] for p in pxs if p['name'].startswith(r)]})
    # 写入文件
    with open('config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump({"port": 7890, "proxies": pxs, "proxy-groups": ags, "rules": ["MATCH,🚀 节点选择"]}, f, allow_unicode=True, sort_keys=False)
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(base64.b64encode("\n".join(valid_links).encode('utf-8')).decode('utf-8'))

if __name__ == "__main__":
    main()
