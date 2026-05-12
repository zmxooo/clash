import base64, json, yaml, os, re, requests, time
from urllib.parse import urlparse, parse_qs, unquote

# 配置常量
HEADERS = {"User-Agent": "ClashMeta"}
MARK = "@zmxooo"
IP_CACHE = {} 

def get_final_label(server: str, remarks: str = "") -> str:
    """识别地理位置：备注匹配优先，IP-API 在线查询补位"""
    if not server: return "🧿 其它地区"
    
    text = unquote(str(remarks)).lower().strip()
    meta = [
        ("🇭🇰 香港节点", r"hk|香港|hongkong|🇭🇰"), ("🇹🇼 台湾节点", r"tw|台湾|台灣|taiwan|🇹🇼"),
        ("🇯🇵 日本节点", r"jp|日本|japan|🇯🇵"), ("🇸🇬 新加坡节点", r"sg|新加坡|singapore|🇸🇬"),
        ("🇰🇷 韩国节点", r"kr|韩国|韓國|korea|🇰🇷"), ("🇺🇸 美国节点", r"us|美国|美國|usa|america|🇺🇸"),
        ("🇬🇧 英国节点", r"gb|uk|英国|英國|united kingdom|🇬🇧"), ("🇩🇪 德国节点", r"de|德国|德國|germany|🇩🇪"),
        ("🇻🇳 越南节点", r"vn|越南|vietnam|🇻🇳"), ("🇱🇹 立陶宛节点", r"lt|立陶宛|lithuania")
    ]
    for label, pattern in meta:
        if re.search(pattern, text): return label

    # 如果备注没写，调用 IP-API 动态识别
    if server in IP_CACHE: return IP_CACHE[server]
    
    # 过滤掉域名，只对纯 IP 或无法从备注识别的情况进行查询 (可选优化)
    try:
        # 【修正点】增加了 /json/ 路径，确保 API 调用正确
        api_url = f"http://ip-api.com{server}?lang=zh-CN"
        resp = requests.get(api_url, timeout=2).json() # 缩短超时到2秒，加快速度
        if resp.get("status") == "success":
            country = resp.get("country", "")
            mapping = {
                "中国": "🇨🇳 中国", "香港": "🇭🇰 香港节点", "台湾": "🇹🇼 台湾节点", 
                "美国": "🇺🇸 美国节点", "日本": "🇯🇵 日本节点", "韩国": "🇰🇷 韩国节点", 
                "新加坡": "🇸🇬 新加坡节点", "德国": "🇩🇪 德国节点", "英国": "🇬🇧 英国节点", "越南": "🇻🇳 越南节点"
            }
            res = mapping.get(country, "🧿 其它地区")
            IP_CACHE[server] = res
            return res
    except:
        pass
    return "🧿 其它地区"

def safe_base64_decode(data: str):
    """通用 Base64 解码"""
    try:
        data = data.strip().replace('-', '+').replace('_', '/')
        data += '=' * (-len(data) % 4)
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except: return ""

def parse_link(link: str):
    """深度解析协议"""
    try:
        link = link.strip()
        if link.startswith('vmess://'):
            b64_part = link[8:].split('#')[0].split('?')[0]
            config = json.loads(safe_base64_decode(b64_part))
            p = {
                "label": get_final_label(config.get("add"), config.get("ps")),
                "name": "", # 占位
                "type": "vmess", "server": config.get("add"), "port": int(config.get("port")),
                "uuid": config.get("id"), "alterId": int(config.get("aid", 0)),
                "cipher": "auto", "tls": str(config.get("tls")).lower() in ["tls", "true"],
                "network": config.get("net", "tcp"), "udp": True, "skip-cert-verify": True
            }
            if p["network"] == "ws":
                p["ws-opts"] = {"path": config.get("path", "/"), "headers": {"Host": config.get("host", "")}}
            return p
        
        elif link.startswith(('vless://', 'trojan://')):
            u = urlparse(link); q = parse_qs(u.query); is_vless = link.startswith('vless://')
            p = {
                "label": get_final_label(u.hostname, u.fragment),
                "name": "", # 占位
                "type": "vless" if is_vless else "trojan", "server": u.hostname, 
                "port": int(u.port or 443), "tls": True, "udp": True, "skip-cert-verify": True,
                "sni": (q.get("sni") or [u.hostname])[0]
            }
            if is_vless:
                p.update({"uuid": u.username, "cipher": "auto"})
                if q.get("security", [""]) == "reality":
                    p["reality-opts"] = {"public-key": q.get("pbk", [""])[0], "short-id": q.get("sid", [""])[0]}
            else: p["password"] = u.username
            return p

        elif link.startswith('ss://'):
            # 简化的 SS 解析逻辑
            u = urlparse(link); fragment = unquote(u.fragment)
            if '@' in u.netloc:
                left, right = u.netloc.split('@', 1)
                method, pwd = safe_base64_decode(left).split(':', 1) if ':' not in left else left.split(':', 1)
                host, port = right.rsplit(':', 1)
            else:
                content = safe_base64_decode(u.netloc)
                method, rest = content.split(':', 1)
                pwd, rest = rest.split('@', 1)
                host, port = rest.rsplit(':', 1)
            return {"label": get_final_label(host, fragment), "name": "", "type": "ss", "server": host, "port": int(port), "cipher": method, "password": pwd, "udp": True}
    except: return None

def main():
    if not os.path.exists('nodes.txt'): return print("❌ 找不到 nodes.txt")
    with open('nodes.txt', 'r', encoding='utf-8') as f: urls = [l.strip() for l in f if l.strip()]
    
    all_proxies, reg_map = [], {}
    print(f"🚀 正在拉取订阅并自动识别 IP 归属地...")

    for url in urls:
        try:
            r = requests.get(url, timeout=15, headers=HEADERS).text
            if "proxies:" in r or url.endswith(('.yaml', '.yml')):
                data = yaml.safe_load(r)
                if isinstance(data, dict) and 'proxies' in data:
                    for p in data['proxies']:
                        p['label'] = get_final_label(p.get('server'), p.get('name', ''))
                        all_proxies.append(p)
                    continue
            
            dec = safe_base64_decode(r.strip()); content = dec if (dec and "://" in dec) else r
            links = re.findall(r'(?:vmess|vless|ss|trojan|hy2|hysteria2)://[^\s#"\'>]+', content)
            for link in links:
                p = parse_link(link)
                if p: all_proxies.append(p)
        except Exception as e: 
            print(f"⚠️ 拉取失败: {url[:40]} | 错误: {e}")

    if not all_proxies: return print("⚠️ 未抓取到有效节点")

    # 按 IP 识别结果动态分组
    for p in all_proxies:
        lbl = p.pop('label', '🧿 其它地区')
        if lbl not in reg_map: reg_map[lbl] = []
        p['name'] = f"{lbl} {MARK} {len(reg_map[lbl]) + 1:02d}"
        reg_map[lbl].append(p['name'])
        # 控制频率防止被 API 封禁，但只有新 IP 才停顿
        if p.get('server') not in IP_CACHE: time.sleep(0.1)

    active_regs = [r for r in ["🇭🇰 香港节点", "🇹🇼 台湾节点", "🇯🇵 日本节点", "🇸🇬 新加坡节点", "🇰🇷 韩国节点", "🇺🇸 美国节点", "🇩🇪 德国节点", "🇬🇧 英国节点", "🇻🇳 越南节点", "🧿 其它地区"] if r in reg_map]
    
    config = {
        "mixed-port": 7890, "allow-lan": True, "mode": "rule", "ipv6": True,
        "log-level": "info",
        "tun": {"enable": True, "stack": "mixed", "auto-route": True},
        "dns": {"enable": True, "enhanced-mode": "fake-ip", "nameserver": ["223.5.5.5", "119.29.29.29", "8.8.8.8"]},
        "proxies": all_proxies,
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择"] + active_regs + ["DIRECT"]},
            {"name": "⚡ 自动选择", "type": "url-test", "url": "http://gstatic.com", "interval": 300, "proxies": [p['name'] for p in all_proxies]},
        ] + [{"name": r, "type": "url-test", "url": "http://gstatic.com", "interval": 300, "proxies": reg_map[r]} for r in active_regs],
        "rules": ["GEOIP,CN,DIRECT", "MATCH,🚀 节点选择"]
    }

    with open('config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)
    print(f"✨ 识别完成！共分类 {len(all_proxies)} 个节点至 {len(active_regs)} 个地区组。文件已保存为 config.yaml")

if __name__ == "__main__": 
    main()
