import base64, json, yaml, urllib.parse, os, re, requests

# ==================== 1. 核心识别：原封不动 ====================
def get_final_label(server, remarks):
    text = urllib.parse.unquote(remarks).lower().strip()
    meta = [
        ("🇭🇰 香港", r"hk|香港|hongkong|🇭🇰"), ("🇹🇼 台湾", r"tw|台湾|台灣|taiwan|🇹🇼"),
        ("🇺🇸 美国", r"us|美国|美國|america|usa|🇺🇸"), ("🇰🇷 韩国", r"kr|韩国|韓國|korea|🇰🇷"),
        ("🇯🇵 日本", r"jp|日本|japan|🇯🇵"), ("🇸🇬 新加坡", r"sg|新加坡|singapore|🇸🇬"),
        ("🇩🇪 德国", r"de|德国|德國|germany|ger|🇩🇪"), ("🇬🇧 英国", r"gb|uk|英国|英國|united kingdom|🇬🇧"),
        ("🇻🇳 越南", r"vn|越南|vietnam|🇻🇳"), ("🇱🇹 立陶宛", r"lt|立陶宛|lithuania"),
        ("🇷🇺 俄罗斯", r"ru|俄罗斯|俄羅斯|russia|🇷🇺"),
    ]
    for label, pattern in meta:
        if re.search(pattern, text): return label
    
    try:
        r = requests.get(f"ip-api.com{server}?lang=zh-CN", timeout=2).json()
        if r.get("status") == "success":
            c = r.get("country")
            country_map = {"中国": "🇨🇳 中国", "香港": "🇭🇰 香港", "台湾": "🇹🇼 台湾", "美国": "🇺🇸 美国", "日本": "🇯🇵 日本", "韩国": "🇰🇷 韩国", "新加坡": "🇸🇬 新加坡", "德国": "🇩🇪 德国", "英国": "🇬🇧 英国", "越南": "🇻🇳 越南", "立陶宛": "🇱🇹 立陶宛"}
            return country_map.get(c, f"🌍 {c}")
    except: pass
    return "🌍 其他"

# ==================== 2. 全量协议解析器：原封不动 ====================
def parse_link(link):
    try:
        if link.startswith('vmess://vmess://'): link = link[8:]
        u = urllib.parse.urlparse(link)
        
        # --- VMess ---
        if link.startswith('vmess://'):
            b64 = link[8:].split('?')
            b64 += '=' * (-len(b64) % 4)
            d = json.loads(base64.b64decode(b64).decode('utf-8'))
            return {"label": get_final_label(d.get("add"), d.get("ps")), "type": "vmess", "server": d.get("add"), "port": int(d.get("port")), "uuid": d.get("id"), "alterId": 0, "cipher": "auto", "tls": d.get("tls") in ["tls", True, 1], "skip-cert-verify": True}

        # --- VLESS / Trojan / TUIC ---
        elif any(link.startswith(p) for p in ['vless://', 'trojan://', 'tuic://']):
            q = urllib.parse.parse_qs(u.query)
            p_type = link.split(':')[0]
            sni = q.get("sni", [""]) or q.get("host", [""]) or [u.hostname]
            p = {"label": get_final_label(u.hostname, u.fragment), "type": p_type, "server": u.hostname, "port": int(u.port), "tls": True, "sni": str(sni), "skip-cert-verify": True, "udp": True}
            if p_type == "vless": p.update({"uuid": u.username, "cipher": "auto"})
            elif p_type == "tuic": p.update({"uuid": u.username, "password": u.password, "alpn": q.get("alpn", ["h3"])})
            else: p["password"] = u.username
            return p

        # --- Shadowsocks (SS) ---
        elif link.startswith('ss://'):
            if "@" in u.netloc:
                userinfo, server = u.netloc.split("@")
                userinfo += '=' * (-len(userinfo) % 4)
                method, password = base64.b64decode(userinfo).decode().split(":", 1)
                host, port = server.split(":")
            else:
                decoded = base64.b64decode(u.netloc + '=' * (-len(u.netloc) % 4)).decode().split(":", 1)
                method = decoded[0]
                password, host_port = decoded[1].rsplit("@", 1)
                host, port = host_port.split(":")
            return {"label": get_final_label(host, u.fragment), "type": "ss", "server": host, "port": int(port), "cipher": method, "password": password, "udp": True}

        # --- Hysteria 1 & 2 ---
        elif any(link.startswith(p) for p in ['hysteria://', 'hysteria2://', 'hy2://']):
            p_type = "hysteria2" if "2" in link or "hy2" in link else "hysteria"
            return {"label": get_final_label(u.hostname, u.fragment), "type": p_type, "server": u.hostname, "port": int(u.port) if u.port else 443, "password": u.username, "auth": u.username, "sni": u.hostname, "skip-cert-verify": True}

    except: return None

# ==================== 3. 主程序逻辑照搬 + 修复 [0] 索引 ====================
def main():
    if not os.path.exists('nodes.txt'): return
    with open('nodes.txt', 'r', encoding='utf-8') as f:
        ls = f.read().splitlines()
    
    pxs, name_count = [], {}
    channel_mark = "@zmxooo"
    
    # 建立小火箭专用列表
    rocket_links = []
    
    for l in ls:
        l = l.strip()
        if not l: continue
        p = parse_link(l)
        if p:
            base_label = p.pop('label')
            name_count[base_label] = name_count.get(base_label, 0) + 1
            p['name'] = f"{base_label} {channel_mark} {name_count[base_label]:02d}"
            
            # 【终极修复】必须取得 split('#')[0] 纯净字符串，才能完美拼接新备注
            clean_url = l.split('#')[0]
            rocket_links.append(f"{clean_url}#{urllib.parse.quote(p['name'])}")
            
            pxs.append(p)

    if not pxs: return

    # 落地文件保存
    with open('rocket_output.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(rocket_links))
        
    with open('clash_output.yaml', 'w', encoding='utf-8') as f:
        yaml.dump({"proxies": pxs}, f, allow_unicode=True, sort_keys=False)
        
    print("✅ 100% 纯净逻辑照搬成功！已成功导出 rocket_output.txt 和 clash_output.yaml")

if __name__ == "__main__":
    main()
