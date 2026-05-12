import base64, json, yaml, os, re, requests, time
from urllib.parse import urlparse, parse_qs, unquote, quote

# 配置常量
HEADERS = {"User-Agent": "ClashMeta"}
MARK = "@zmxooo"
IP_CACHE = {} 

def get_final_label(server: str, remarks: str = "") -> str:
    """地理位置识别：备注优先，IP-API 补位"""
    if not server: return "🧿 其它地区"
    text = unquote(str(remarks)).lower().strip()
    meta = [
        ("🇭🇰 香港节点", r"hk|香港|hongkong|🇭🇰"), ("🇹🇼 台湾节点", r"tw|台湾|台灣|taiwan|🇹🇼"),
        ("🇯🇵 日本节点", r"jp|日本|japan|🇯🇵"), ("🇸🇬 新加坡节点", r"sg|新加坡|singapore|🇸🇬"),
        ("🇰🇷 韩国节点", r"kr|韩国|韓國|korea|🇰🇷"), ("🇺🇸 美国节点", r"us|美国|美國|usa|america|🇺🇸"),
        ("🇬🇧 英国节点", r"gb|uk|英国|英國|united kingdom|🇬🇧"), ("🇩🇪 德国节点", r"de|德国|德國|germany|🇩🇪"),
        ("🇻🇳 越南节点", r"vn|越南|vietnam|🇻🇳")
    ]
    for label, pattern in meta:
        if re.search(pattern, text): return label

    if server in IP_CACHE: return IP_CACHE[server]
    try:
        # 修正 API 路径，添加 /json/
        resp = requests.get(f"http://ip-api.com{server}?lang=zh-CN", timeout=2).json()
        if resp.get("status") == "success":
            country = resp.get("country", "")
            mapping = {"中国": "🇨🇳 中国", "香港": "🇭🇰 香港节点", "台湾": "🇹🇼 台湾节点", "美国": "🇺🇸 美国节点", "日本": "🇯🇵 日本节点", "韩国": "🇰🇷 韩国节点", "新加坡": "🇸🇬 新加坡节点"}
            res = mapping.get(country, "🧿 其它地区")
            IP_CACHE[server] = res
            return res
    except: pass
    return "🧿 其它地区"

def safe_b64decode(data: str):
    try:
        data = data.strip().replace('-', '+').replace('_', '/')
        data += '=' * (-len(data) % 4)
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except: return ""

def safe_b64encode(data: str):
    return base64.b64encode(data.encode('utf-8')).decode('utf-8')

def parse_link(link: str):
    """解析协议并提取核心参数"""
    try:
        link = link.strip()
        if link.startswith('vmess://'):
            config = json.loads(safe_b64decode(link[8:]))
            return {
                "label": get_final_label(config.get("add"), config.get("ps")),
                "type": "vmess", "server": config.get("add"), "port": int(config.get("port")),
                "uuid": config.get("id"), "aid": int(config.get("aid", 0)),
                "net": config.get("net", "tcp"), "path": config.get("path", "/"),
                "host": config.get("host", ""), "tls": str(config.get("tls")).lower() in ["tls", "true"]
            }
        elif link.startswith(('vless://', 'trojan://')):
            u = urlparse(link); q = parse_qs(u.query); is_vless = link.startswith('vless://')
            p = {
                "label": get_final_label(u.hostname, u.fragment),
                "type": "vless" if is_vless else "trojan", "server": u.hostname, "port": int(u.port or 443),
                "uuid": u.username, "password": u.username, "sni": (q.get("sni") or [u.hostname])[0],
                "pbk": q.get("pbk", [""])[0], "sid": q.get("sid", [""])[0], "flow": q.get("flow", [""])[0]
            }
            return p
        elif link.startswith('ss://'):
            u = urlparse(link); content = u.netloc if '@' in u.netloc else safe_b64decode(u.netloc)
            left, right = content.split('@', 1); method, pwd = left.split(':', 1)
            host, port = right.rsplit(':', 1)
            return {"label": get_final_label(host, u.fragment), "type": "ss", "server": host, "port": int(port), "cipher": method, "password": pwd}
    except: return None

def main():
    if not os.path.exists('nodes.txt'): return print("❌ 找不到 nodes.txt")
    with open('nodes.txt', 'r', encoding='utf-8') as f: urls = [l.strip() for l in f if l.strip()]
    
    all_proxies, reg_map = [], {}
    print(f"🚀 正在处理节点并统一名称...")

    for url in urls:
        try:
            r = requests.get(url, timeout=10, headers=HEADERS).text
            dec = safe_b64decode(r.strip()); content = dec if "://" in dec else r
            links = re.findall(r'(?:vmess|vless|ss|trojan)://[^\s#"\'>]+', content)
            for link in links:
                p = parse_link(link)
                if p: all_proxies.append(p)
        except: pass

    if not all_proxies: return print("⚠️ 未抓取到有效节点")

    # --- 统一化命名与字段清洗 ---
    clash_proxies = []
    sub_links = []
    
    for p in all_proxies:
        lbl = p.pop('label', '🧿 其它地区')
        if lbl not in reg_map: reg_map[lbl] = []
        
        # 1. 生成唯一统一名称
        new_name = f"{lbl} {MARK} {len(reg_map[lbl]) + 1:02d}"
        reg_map[lbl].append(new_name)

        # 2. 构建用于 Clash 的字典 (con 统一)
        cp = {"name": new_name, "type": p['type'], "server": p['server'], "port": p['port'], "udp": True}
        if p['type'] == 'vmess':
            cp.update({"uuid": p['uuid'], "alterId": p['aid'], "cipher": "auto", "tls": p['tls'], "network": p['net']})
            if p['net'] == 'ws': cp["ws-opts"] = {"path": p['path'], "headers": {"Host": p['host']}}
        elif p['type'] == 'vless':
            cp.update({"uuid": p['uuid'], "cipher": "auto", "tls": True, "sni": p['sni']})
            if p['pbk']: cp["reality-opts"] = {"public-key": p['pbk'], "short-id": p['sid']}
        elif p['type'] == 'trojan':
            cp.update({"password": p['password'], "sni": p['sni'], "skip-cert-verify": True})
        elif p['type'] == 'ss':
            cp.update({"cipher": p['cipher'], "password": p['password']})
        clash_proxies.append(cp)

        # 3. 逆向构建 Base64 链接 (ind 统一)
        try:
            if p['type'] == 'vmess':
                v_json = {"v":"2","ps":new_name,"add":p['server'],"port":p['port'],"id":p['uuid'],"aid":p['aid'],"net":p['net'],"type":"none","host":p['host'],"path":p['path'],"tls":"tls" if p['tls'] else ""}
                sub_links.append(f"vmess://{safe_b64encode(json.dumps(v_json))}")
            elif p['type'] == 'vless':
                sub_links.append(f"vless://{p['uuid']}@{p['server']}:{p['port']}?encryption=none&security={'reality' if p['pbk'] else 'tls'}&sni={p['sni']}&pbk={p['pbk']}&sid={p['sid']}#{quote(new_name)}")
            elif p['type'] == 'trojan':
                sub_links.append(f"trojan://{p['password']}@{p['server']}:{p['port']}?sni={p['sni']}#{quote(new_name)}")
            elif p['type'] == 'ss':
                sub_links.append(f"ss://{safe_b64encode(f'{p['cipher']}:{p['password']}')}@{p['server']}:{p['port']}#{quote(new_name)}")
        except: pass

    # --- 输出 1: config.yaml ---
    active_regs = [r for r in ["🇭🇰 香港节点", "🇹🇼 台湾节点", "🇯🇵 日本节点", "🇸🇬 新加坡节点", "🇰🇷 韩国节点", "🇺🇸 美国节点", "🧿 其它地区"] if r in reg_map]
    config = {
        "mixed-port": 7890, "allow-lan": True, "mode": "rule",
        "proxies": clash_proxies + [{"name": "DIRECT", "type": "direct"}],
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择"] + active_regs + ["DIRECT"]},
            {"name": "⚡ 自动选择", "type": "url-test", "url": "http://gstatic.com", "interval": 300, "proxies": [p['name'] for p in clash_proxies]},
        ] + [{"name": r, "type": "url-test", "url": "http://gstatic.com", "interval": 300, "proxies": reg_map[r]} for r in active_regs],
        "rules": ["GEOIP,CN,DIRECT", "MATCH,🚀 节点选择"]
    }
    with open('config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)

    # --- 输出 2: index.html (Base64 订阅) ---
    full_base64 = safe_b64encode("\n".join(sub_links))
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(full_base64)

    print(f"✨ 成功！config.yaml 和 index.html (Base64) 均已完成名称统一。")

if __name__ == "__main__": main()
