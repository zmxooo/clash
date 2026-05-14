import base64, json, yaml, urllib.parse, os

def parse_vmess(link):
    try:
        p = link[8:]
        p += '=' * (-len(p) % 4)
        d = json.loads(base64.b64decode(p).decode('utf-8'))
        n = d.get("ps", "VMess").replace("英國", "英国").replace("美國", "美国").replace("❓", "").strip()
        d["ps"] = n
        new_link = "vmess://" + base64.b64encode(json.dumps(d).encode('utf-8')).decode('utf-8')
        proxy = {"name": n, "type": "vmess", "server": d.get("add"), "port": int(d.get("port", 180)), "uuid": d.get("id"), "alterId": 0, "cipher": "auto", "tls": d.get("tls") == "tls", "skip-cert-verify": True}
        return proxy, new_link
    except: return None, None

def parse_hy2(link):
    try:
        u = urllib.parse.urlparse(link)
        n = urllib.parse.unquote(u.fragment).replace("英國", "英国").replace("美國", "美国").replace("❓", "").strip()
        new_link = f"hysteria2://{u.netloc}{u.path}?{u.query}#{urllib.parse.quote(n)}"
        proxy = {"name": n, "type": "hysteria2", "server": u.hostname, "port": u.port, "password": u.username, "sni": u.hostname, "skip-cert-verify": True}
        return proxy, new_link
    except: return None, None

def main():
    if not os.path.exists('nodes.txt'): return
    with open('nodes.txt', 'r', encoding='utf-8') as f:
        ls = f.read().splitlines()
    
    pxs = []
    raw_links = []
    name_count = {} # 用来记录名字出现的次数

    for l in ls:
        l = l.strip()
        if not l: continue
        p, nl = None, None
        if l.startswith('vmess://'): p, nl = parse_vmess(l)
        elif l.startswith('hysteria2://'): p, nl = parse_hy2(l)
        
        if p:
            # --- 核心逻辑：处理重名 ---
            origin_name = p['name']
            if origin_name in name_count:
                name_count[origin_name] += 1
                p['name'] = f"{origin_name} {name_count[origin_name]}"
            else:
                name_count[origin_name] = 0
            
            pxs.append(p)
            raw_links.append(nl)
    
    # --- 生成 Clash 配置 ---
    regs = {"🇭🇰 香港": "香港", "🇹🇼 台湾": "台湾", "🇺🇸 美国": "美国", "🇬🇧 英国": "英国", "🇰🇷 韩国": "韩国", "🇯🇵 日本": "日本"}
    gps = {k: [] for k in regs}
    gps["🌍 其他"] = []
    for p in pxs:
        for k, v in regs.items():
            if v in p['name']: gps[k].append(p['name']); break
        else: gps["🌍 其他"].append(p['name'])
    
    ags = [{"name": k, "type": "select", "proxies": v} for k, v in gps.items() if v]
    cf = {
        "port": 7890, "socks-port": 7891, "allow-lan": True, "mode": "rule", "log-level": "info",
        "proxies": pxs,
        "proxy-groups": [{"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动择优"] + [g['name'] for g in ags] + ["DIRECT"]}, {"name": "⚡ 自动择优", "type": "url-test", "url": "http://gstatic.com", "interval": 300, "proxies": [p['name'] for p in pxs]}] + ags,
        "rules": ["GEOIP,CN,DIRECT", "MATCH,🚀 节点选择"]
    }
    with open('config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(cf, f, allow_unicode=True, sort_keys=False)

    # --- 生成通用订阅 ---
    sub_content = "\n".join(raw_links)
    b64_sub = base64.b64encode(sub_content.encode('utf-8')).decode('utf-8')
    with open('subscribe.txt', 'w', encoding='utf-8') as f:
        f.write(b64_sub)

if __name__ == "__main__": main()
