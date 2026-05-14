import base64, json, yaml, urllib.parse, os, re, requests

# --- 1. 核心识别：IP 真实归属地查询 + 备注匹配 ---
def get_final_label(server, remarks):
    # 第一优先级：从备注识别国家
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
    
    # 第二优先级：备注无国家信息，则查询 IP 真实地理位置
    try:
        # 使用 ip-api.com 进行高精度查询
        r = requests.get(f"http://ip-api.com{server}?lang=zh-CN", timeout=3).json()
        if r.get("status") == "success":
            c = r.get("country")
            # API 返回名映射到带图标的标签
            country_map = {
                "中国": "🇨🇳 中国", "香港": "🇭🇰 香港", "台湾": "🇹🇼 台湾", "美国": "🇺🇸 美国", 
                "日本": "🇯🇵 日本", "韩国": "🇰🇷 韩国", "新加坡": "🇸🇬 新加坡", "德国": "🇩🇪 德国", 
                "英国": "🇬🇧 英国", "越南": "🇻🇳 越南", "立陶宛": "🇱🇹 立陶宛"
            }
            return country_map.get(c, f"🌍 {c}")
    except: pass
    return "🌍 其他"

# --- 2. 全协议通用解析器 ---
def parse_link(link):
    try:
        if link.startswith('vmess://vmess://'): link = link[8:]
        u = urllib.parse.urlparse(link)
        
        # VMess 解析 (补全 alterId)
        if link.startswith('vmess://'):
            b64 = link[8:].split('?')
            b64 += '=' * (-len(b64) % 4)
            d = json.loads(base64.b64decode(b64).decode('utf-8'))
            return {"label": get_final_label(d.get("add"), d.get("ps")), "type": "vmess", "server": d.get("add"), "port": int(d.get("port")), "uuid": d.get("id"), "alterId": 0, "cipher": "auto", "tls": d.get("tls") in ["tls", True, 1], "skip-cert-verify": True}

        # VLESS / Trojan / TUIC 解析 (修正 sni 类型)
        elif any(link.startswith(p) for p in ['vless://', 'trojan://', 'tuic://']):
            q = urllib.parse.parse_qs(u.query)
            p_type = link.split(':')[0]
            sni = (q.get("sni", [""]) or q.get("host", [""]) or [u.hostname])
            p = {"label": get_final_label(u.hostname, u.fragment), "type": p_type, "server": u.hostname, "port": int(u.port), "tls": True, "sni": str(sni), "skip-cert-verify": True, "udp": True}
            if p_type == "vless": p.update({"uuid": u.username, "cipher": "auto"})
            else: p["password"] = u.username
            return p

        # Shadowsocks (SS) 解析
        elif link.startswith('ss://'):
            server_part = u.netloc.split("@")[-1]
            host = server_part.split(":")[0]
            port = server_part.split(":")[1] if ":" in server_part else 443
            return {"label": get_final_label(host, u.fragment), "type": "ss", "server": host, "port": int(port), "cipher": "aes-256-gcm", "password": u.username if "@" in u.netloc else "password", "udp": True}

        # Hysteria 1 & 2 解析 (全兼容)
        elif any(link.startswith(p) for p in ['hysteria://', 'hysteria2://', 'hy2://']):
            p_type = "hysteria2" if "2" in link or "hy2" in link else "hysteria"
            return {"label": get_final_label(u.hostname, u.fragment), "type": p_type, "server": u.hostname, "port": int(u.port) if u.port else 443, "password": u.username, "sni": u.hostname, "skip-cert-verify": True}
            
    except Exception as e:
        print(f"解析出错: {e}")
        return None

# --- 3. 主程序：文件分发 ---
def main():
    if not os.path.exists('nodes.txt'): return
    with open('nodes.txt', 'r', encoding='utf-8') as f:
        ls = f.read().splitlines()
    
    pxs, name_count, valid_links = [], {}, []
    channel_mark = "@zmxooo" # 你的专属后缀
    
    for l in ls:
        l = l.strip()
        # 排除空行和不小心粘错的代码行
        if not l or any(l.startswith(s) for s in ['import ', 'def ', 'class ']): continue
        p = parse_link(l)
        if p:
            valid_links.append(l)
            base_label = p.pop('label')
            name_count[base_label] = name_count.get(base_label, 0) + 1
            # 统一命名：国家 + 频道 + 序号
            p['name'] = f"{base_label} {channel_mark} {name_count[base_label]:02d}"
            pxs.append(p)

    if not pxs: return

    # 动态生成 Clash 测速分组
    found_regions = sorted(list(set([p['name'].split(' ')[0] + " " + p['name'].split(' ')[1] for p in pxs if ' ' in p['name']])))
    ags = [{"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择", "DIRECT"] + found_regions}]
    ags.append({"name": "⚡ 自动选择", "type": "url-test", "url": "http://gstatic.com", "interval": 300, "proxies": [p['name'] for p in pxs]})
    
    for r in found_regions:
        ags.append({
            "name": r, "type": "url-test", "url": "http://gstatic.com", 
            "interval": 300, "proxies": [p['name'] for p in pxs if p['name'].startswith(r)]
        })
    
    # 导出 A：Clash 配置 (config.yaml)
    with open('config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump({"port": 7890, "proxies": pxs, "proxy-groups": ags, "rules": ["MATCH,🚀 节点选择"]}, f, allow_unicode=True, sort_keys=False)
    
    # 导出 B：通用订阅 (index.html) 给小火箭和 V2Ray
    sub_b64 = base64.b64encode("\n".join(valid_links).encode('utf-8')).decode('utf-8')
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(sub_b64)

if __name__ == "__main__":
    main()
