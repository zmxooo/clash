import base64, json, yaml, urllib.parse, os, re, requests, time

# 1. 核心识别：优先备注，其次 IP
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
            c = r.get("country")
            m = {"中国": "🇨🇳 中国", "香港": "🇭🇰 香港", "台湾": "🇹🇼 台湾", "美国": "🇺🇸 美国", "日本": "🇯🇵 日本", "韩国": "🇰🇷 韩国", "新加坡": "🇸🇬 新加坡", "德国": "🇩🇪 德国", "英国": "🇬🇧 英国", "越南": "🇻🇳 越南", "立陶宛": "🇱🇹 立陶宛"}
            return m.get(c, f"🌍 {c}")
    except: pass
    return "🌍 其他"

# 2. 全量解析逻辑（严格检查数据类型）
def parse_link(link):
    try:
        link = link.replace('vmess://vmess://', 'vmess://').strip()
        # --- VMess ---
        if link.startswith('vmess://'):
            # 修正：先取字符串，再补全，再解码
            b64_str = link[8:].split('#')[0].split('?')[0]
            b64_str += '=' * (-len(b64_str) % 4)
            d = json.loads(base64.b64decode(b64_str).decode('utf-8'))
            return {"label": get_final_label(d.get("add"), d.get("ps")), "type": "vmess", "server": d.get("add"), "port": int(d.get("port")), "uuid": d.get("id"), "alterId": 0, "cipher": "auto", "tls": d.get("tls") in ["tls", True, 1, "1"], "skip-cert-verify": True}
        
        u = urllib.parse.urlparse(link)
        # --- VLESS / Trojan ---
        if any(link.startswith(p) for p in ['vless://', 'trojan://']):
            q = urllib.parse.parse_qs(u.query)
            p_type = "vless" if "vless" in link else "trojan"
            # 核心修正：取出列表中的第一个字符串，防止 Clash 报错
            raw_sni = q.get("sni", [""]) or q.get("host", [""]) or [u.hostname]
            sni_str = raw_sni[0] if isinstance(raw_sni, list) else raw_sni
            p = {"label": get_final_label(u.hostname, u.fragment), "type": p_type, "server": u.hostname, "port": int(u.port), "tls": True, "sni": str(sni_str), "skip-cert-verify": True, "udp": True}
            if p_type == "vless": p.update({"uuid": u.username, "cipher": "auto"})
            else: p["password"] = u.username
            return p
        # --- Shadowsocks ---
        elif link.startswith('ss://'):
            server_part = u.netloc.split("@")[-1]
            host_port = server_part.split(":")
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 443
            return {"label": get_final_label(host, u.fragment), "type": "ss", "server": host, "port": port, "cipher": "aes-256-gcm", "password": u.username if "@" in u.netloc else "password", "udp": True}
        # --- Hysteria2 ---
        elif any(link.startswith(p) for p in ['hy2://', 'hysteria2://']):
            return {"label": get_final_label(u.hostname, u.fragment), "type": "hysteria2", "server": u.hostname, "port": int(u.port) if u.port else 443, "password": u.username, "auth": u.username, "sni": u.hostname, "skip-cert-verify": True}
    except: return None

def main():
    if not os.path.exists('nodes.txt'): return
    with open('nodes.txt', 'r', encoding='utf-8') as f:
        ls = f.read().splitlines()
    pxs, name_count, valid = [], {}, []
    channel_mark = "@zmxooo"
    for l in ls:
        l = l.strip()
        if not l or any(l.startswith(s) for s in ['import', 'def', 'git']): continue
        p = parse_link(l)
        if p:
            valid.append(l)
            lbl = p.pop('label')
            name_count[lbl] = name_count.get(lbl, 0) + 1
            p['name'] = f"{lbl} {channel_mark} {name_count[lbl]:02d}"
            pxs.append(p)
            time.sleep(0.05)
    if not pxs: 
        print("未识别到有效节点")
        return
    # 动态构建分组（修复分组名）
    group_labels = sorted(list(set([p['name'].split(' @')[0] for p in pxs if ' @' in p['name']])))
    ags = [{"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择", "DIRECT"] + group_labels}]
    ags.append({"name": "⚡ 自动选择", "type": "url-test", "url": "http://gstatic.com", "interval": 300, "proxies": [p['name'] for p in pxs]})
    for r in group_labels:
        ags.append({"name": r, "type": "url-test", "url": "http://gstatic.com", "interval": 300, "proxies": [p['name'] for p in pxs if p['name'].startswith(r)]})
    # 写入 Clash
    with open('config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump({"port": 7890, "proxies": pxs, "proxy-groups": ags, "rules": ["MATCH,🚀 节点选择"]}, f, allow_unicode=True, sort_keys=False)
    # 写入小火箭 Base64
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(base64.b64encode("\n".join(valid).encode('utf-8')).decode('utf-8'))
    print("转换成功！文件已生成。")

if __name__ == "__main__":
    main()
