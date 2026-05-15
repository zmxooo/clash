import base64, json, yaml, urllib.parse, os, re, requests, time
from collections import defaultdict

# --- 配置区 ---
CHANNEL_MARK = "zmxooo"
TEST_URL = "http://gstatic.com"
IP_CACHE = {}

# 1. 扩展高精度国家/地区映射表
EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "美国": "🇺🇸", "日本": "🇯🇵", 
    "新加坡": "🇸🇬", "韩国": "🇰🇷", "德国": "🇩🇪", "英国": "🇬🇧",
    "俄罗斯": "🇷🇺", "法国": "🇫🇷", "加拿大": "🇨🇦", "荷兰": "🇳🇱",
    "泰国": "🇹🇭", "越南": "🇻🇳", "印度": "🇮🇳", "澳大利亚": "🇦🇺"
}

def get_final_label(server, remarks):
    # 统一转换成小写并解码，处理类似 %F0%9F%87... 的 URL 编码
    text = urllib.parse.unquote(str(remarks)).lower().strip()
    server_str = str(server).lower().strip()
    
    # 2. 强化特征正则：涵盖常见混淆标识（如国旗、缩写等）
    meta = [
        ("香港", r"hk|香港|hongkong|🦩hk|🇭🇰"), 
        ("台湾", r"tw|台湾|台灣|taiwan|🇹🇼"), 
        ("美国", r"us|美国|美|united states|america|🇺🇸"), 
        ("日本", r"jp|日本|japan|🇯🇵"),
        ("新加坡", r"sg|新加坡|singapore|🇸🇬"), 
        ("韩国", r"kr|韩国|韓國|korea|🇰🇷")
    ]
    
    # 优先匹配节点备注中的关键词
    for name, pattern in meta:
        if re.search(pattern, text): 
            return f"{EMOJI_MAP.get(name, '🌍')}{name}"
            
    # 其次匹配域名或地址中的关键字
    for name, pattern in meta:
        if re.search(pattern, server_str): 
            return f"{EMOJI_MAP.get(name, '🌍')}{name}"
    
    # 3. 检查缓存提高效率
    if server in IP_CACHE: 
        return IP_CACHE[server]
        
    # 4. 在线 API 识别兜底：处理无特征的纯 IP 或纯英文域名
    if server_str:
        # 清理可能带有的端口号
        clean_ip = server_str.split(':')[0]
        try:
            time.sleep(0.3) 
            resp = requests.get(f"http://ip-api.com{clean_ip}?lang=zh-CN", timeout=3).json()
            if resp.get("status") == "success":
                country = resp.get("country")
                if country:
                    label = f"{EMOJI_MAP.get(country, '🌍')}{country}"
                    IP_CACHE[server] = label
                    return label
        except Exception as e:
            print(f"[!] API 查询失败 -> 节点地址: {clean_ip}, 错误: {e}")
            
    return "🧿其它地区"

def fix_base64(s):
    s = "".join(s.split())
    return s + '=' * (-len(s) % 4)

def rebuild_node(link, new_name):
    try:
        if link.startswith('vmess://'):
            b64_part = link[8:].split('#')[0]
            try:
                d = json.loads(base64.b64decode(fix_base64(b64_part)).decode('utf-8', 'ignore'))
            except Exception as e:
                print(f"[x] VMess Base64/JSON 解析失败 (可能是由于链接截断崩溃): {link[:30]}...")
                return None, None, None
                
            raw_ps = d.get("ps", "")
            label = get_final_label(d.get("add"), raw_ps)
            
            std_vmess = {
                "v": "2", "ps": new_name, "add": str(d.get("add")).strip(),
                "port": str(d.get("port")), "id": str(d.get("id")), "aid": str(d.get("aid", "0")),
                "net": d.get("net", "tcp"), "type": d.get("type", "none"),
                "host": d.get("host", ""), "path": d.get("path", ""), "tls": d.get("tls", "")
            }
            proxy = {
                "name": new_name, "type": "vmess", "server": std_vmess["add"],
                "port": int(std_vmess["port"]), "uuid": std_vmess["id"], "alterId": int(std_vmess["aid"]),
                "cipher": "auto", "tls": True if str(std_vmess["tls"]).lower() in ["tls", "1", "true"] else False,
                "network": std_vmess["net"], "skip-cert-verify": True
            }
            if proxy["network"] == "ws":
                proxy["ws-opts"] = {"path": std_vmess["path"], "headers": {"Host": std_vmess["host"]}}
            return label, proxy, f"vmess://{base64.b64encode(json.dumps(std_vmess).encode()).decode()}"

        # 针对通用非 vmess 节点
        clean_link = link.split('#')[0]
        u = urllib.parse.urlparse(clean_link)
        scheme = u.scheme.lower()
        
        orig_fragment = urllib.parse.urlparse(link).fragment
        label = get_final_label(u.hostname, orig_fragment)
        proxy = {"name": new_name, "server": u.hostname, "port": u.port if u.port else 443, "skip-cert-verify": True}

        if scheme == "ss":
            user_info = u.username if u.username else base64.b64decode(fix_base64(u.netloc.split('@')[0])).decode()
            method, password = user_info.split(':') if ':' in user_info else ("aes-256-gcm", user_info)
            proxy.update({"type": "ss", "cipher": method, "password": password})
        elif scheme == "trojan":
            proxy.update({"type": "trojan", "password": u.username, "sni": u.hostname})
        elif scheme == "vless":
            params = dict(urllib.parse.parse_qsl(u.query))
            proxy.update({
                "type": "vless", "uuid": u.username, "cipher": "auto",
                "tls": True if params.get("security") in ["tls", "reality"] else False,
                "network": params.get("type", "tcp"), "sni": params.get("sni", u.hostname)
            })
            if params.get("security") == "reality":
                proxy.update({"reality-opts": {"public-key": params.get("pbk", ""), "short-id": params.get("sid", "")}})
        elif scheme in ["hysteria2", "hy2"]:
            proxy.update({"type": "hysteria2", "password": u.username, "sni": u.hostname})
        elif scheme in ["http", "https"]:
            user_info = u.netloc.split('@')[0] if '@' in u.netloc else ''
            user, pwd = user_info.split(':') if ':' in user_info else ('', '')
            proxy.update({"type": "http", "username": user, "password": pwd, "tls": True if scheme == "https" else False})
        else: 
            print(f"[?] 暂不支持的节点协议方案: {scheme} -> {link[:30]}...")
            return None, None, None

        return label, proxy, f"{clean_link}#{urllib.parse.quote(new_name)}"
    except Exception as e: 
        print(f"[!] 节点结构重组发生内部错误: {e}")
        return None, None, None

def main():
    if not os.path.exists('nodes.txt'): 
        print("[-] 未找到 nodes.txt 文件")
        return
    with open('nodes.txt', 'r', encoding='utf-8') as f:
        raw_links = list(dict.fromkeys([l.strip() for l in f if "://" in l]))
    
    print(f"[*] 开始处理，共发现 {len(raw_links)} 个去重原始链接")
    region_map = defaultdict(list)
    clash_proxies, rocket_links = [], []
    
    for l in raw_links:
        lbl, _, _ = rebuild_node(l, "TEMP_PLACEHOLDER")
        if not lbl: 
            continue
            
        idx = len(region_map[lbl]) + 1
        new_name = f"{lbl} {CHANNEL_MARK}{idx:02d}"
        
        label, proxy, r_link = rebuild_node(l, new_name)
        if proxy and r_link:
            region_map[label].append(new_name)
            clash_proxies.append(proxy)
            rocket_links.append(r_link)

    if rocket_links:
        with open('index.html', 'w', encoding='utf-8') as f:
            f.write(base64.b64encode("\n".join(rocket_links).encode()).decode())
        print(f"[+] Shadowrocket 订阅已成功导出至 index.html")
    
    if clash_proxies:
        active_regions = sorted(list(region_map.keys()))
        groups = [
            {"name": "🚀节点选择", "type": "select", "proxies": ["🎬自动选择"] + active_regions + ["DIRECT"]},
            {"name": "🎬自动选择", "type": "url-test", "url": TEST_URL, "interval": 300, "proxies": [p['name'] for p in clash_proxies]}
        ]
        for r in active_regions:
            groups.append({"name": r, "type": "url-test", "url": TEST_URL, "interval": 300, "proxies": region_map[r]})
        
        config = {"mixed-port": 7890, "allow-lan": True, "mode": "rule", "proxies": clash_proxies, "proxy-groups": groups, "rules": ["MATCH,🚀节点选择"]}
        with open('clash_config.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(config, f, allow_unicode=True, sort_keys=False)
        print(f"[+] Clash 配置文件已成功导出至 clash_config.yaml")

if __name__ == "__main__":
    main()
