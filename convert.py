import base64, json, yaml, os, re, requests, time
from urllib.parse import urlparse, parse_qs, unquote, quote

# 配置常量
HEADERS = {"User-Agent": "ClashMeta"}
MARK = "@zmxooo"
IP_CACHE = {} 

def get_final_label(server: str, remarks: str = "") -> str:
    """识别地理位置：保留你的原始识别逻辑，仅修复 API 路径"""
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
        # 补全 /json/ 路径
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
    """【完全还原版】回归你最初的解析结构，确保不丢节点"""
    try:
        link = link.strip()
        if link.startswith('vmess://'):
            b64_part = link[8:].split('#')[0].split('?')[0]
            config = json.loads(safe_b64decode(b64_part))
            p = {
                "label": get_final_label(config.get("add"), config.get("ps")),
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
            u = urlparse(link); content = u.netloc if '@' in u.netloc else safe_b64decode(u.netloc)
            left, right = content.split('@', 1); method, pwd = left.split(':', 1)
            host, port = right.rsplit(':', 1)
            return {"label": get_final_label(host, u.fragment), "type": "ss", "server": host, "port": int(port), "cipher": method, "password": pwd, "udp": True}
    except: return None

def main():
    if not os.path.exists('nodes.txt'): return
    with open('nodes.txt', 'r', encoding='utf-8') as f: urls = [l.strip() for l in f if l.strip()]
    
    all_proxies, reg_map = [], {}
    for url in urls:
        try:
            r = requests.get(url, timeout=15, headers=HEADERS).text
            dec = safe_b64decode(r.strip()); content = dec if (dec and "://" in dec) else r
            links = re.findall(r'(?:vmess|vless|ss|trojan|hy2|hysteria2)://[^\s#"\'>]+', content)
            for link in links:
                p = parse_link(link)
                if p: all_proxies.append(p)
        except: pass

    if not all_proxies: return print("❌ 抓取失败，请检查 nodes.txt 链接")

    clash_proxies, sub_links = [], []
    for p in all_proxies:
        lbl = p.pop('label', '🧿 其它地区')
        if lbl not in reg_map: reg_map[lbl] = []
        new_name = f"{lbl} {MARK} {len(reg_map[lbl]) + 1:02d}"
        reg_map[lbl].append(new_name)
        
        # 强制同步内部名称
        p['name'] = new_name
        clash_proxies.append(p)

        # 逆向生成订阅
        try:
            if p['type'] == 'vmess':
                v_j = {"v":"2","ps":new_name,"add":p['server'],"port":p['port'],"id":p['uuid'],"aid":p['alterId'],"net":p['network'],"type":"none","host":p.get('ws-opts',{}).get('headers',{}).get('Host',''),"path":p.get('ws-opts',{}).get('path','/'),"tls":"tls" if p['tls'] else ""}
                sub_links.append(f"vmess://{safe_b64encode(json.dumps(v_j))}")
            elif p['type'] == 'vless':
                sub_links.append(f"vless://{p['uuid']}@{p['server']}:{p['port']}?encryption=none&security={'reality' if 'reality-opts' in p else 'tls'}&sni={p['sni']}#{quote(new_name)}")
            elif p['type'] == 'trojan':
                sub_links.append(f"trojan://{p['password']}@{p['server']}:{p['port']}?sni={p['sni']}#{quote(new_name)}")
            elif p['type'] == 'ss':
                sub_links.append(f"ss://{safe_b64encode(p['cipher']+':'+p['password'])}@{p['server']}:{p['port']}#{quote(new_name)}")
        except: pass

    # 写入 config.yaml
    active_regs = [r for r in ["🇭🇰 香港节点", "🇹🇼 台湾节点", "🇯🇵 日本节点", "🇸🇬 新加坡节点", "🇺🇸 美国节点", "🧿 其它地区"] if r in reg_map]
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

    # 写入 index.html 和 sub.txt
    final_b64 = safe_b64encode("\n".join(sub_links))
    for filename in ['index.html', 'sub.txt']:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(final_b64)

if __name__ == "__main__": main()
