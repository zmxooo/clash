import base64, json, yaml, urllib.parse, os, re, requests, time
from collections import defaultdict

CHANNEL_MARK = "@zmxooo"

def get_final_label(server, remarks):
    text = urllib.parse.unquote(str(remarks)).lower().strip()
    # 1. 极大增强正则匹配库，减少对 IP 查询的依赖
    meta = [
        ("🇭🇰 香港节点", r"hk|香港|hongkong|hkg"), 
        ("🇹🇼 台湾节点", r"tw|台湾|台灣|taiwan|tpe"),
        ("🇺🇸 美国节点", r"us|美国|美國|united states|usa|lax|sjc"), 
        ("🇬🇧 英国节点", r"gb|uk|英国|英國|london"),
        ("🇰🇷 韩国节点", r"kr|韩国|韓國|korea|sel"), 
        ("🇯🇵 日本节点", r"jp|日本|japan|nrt|hnd"),
        ("🇸🇬 新加坡节点", r"sg|新加坡|singapore|sin"), 
        ("🇻🇳 越南节点", r"vn|越南|vietnam"),
        ("🇱🇹 立陶宛节点", r"lt|立陶宛"),
    ]
    for label, pattern in meta:
        if re.search(pattern, text): 
            return label
    
    # 2. 正则没匹配到再查 IP，并增加延时防止封禁
    try:
        r = requests.get(f"http://ip-api.com{server}?lang=zh-CN", timeout=3).json()
        if r.get("status") == "success":
            c = r.get("country")
            m = {
                "香港": "🇭🇰 香港节点", "台湾": "🇹🇼 台湾节点", "美国": "🇺🇸 美国节点",
                "英国": "🇬🇧 英国节点", "韩国": "🇰🇷 韩国节点", "日本": "🇯🇵 日本节点",
                "新加坡": "🇸🇬 新加坡节点", "越南": "🇻🇳 越南节点"
            }
            # 查完休眠一下，保证 API 稳定性
            time.sleep(1.2)
            return m.get(c, f"🌍 {c}节点")
    except:
        pass
    return "🧿 其它地区"

def parse_link(link):
    try:
        link = link.replace('vmess://vmess://', 'vmess://').strip()
        u = urllib.parse.urlparse(link)
        if link.startswith('vmess://'):
            b64 = link[8:].split('#')[0].split('?')[0]
            b64 += '=' * (-len(b64) % 4)
            # 解决乱码：自动尝试 UTF-8 和 GBK
            raw_data = base64.b64decode(b64)
            try: decoded_str = raw_data.decode('utf-8')
            except: decoded_str = raw_data.decode('gbk')
            
            d = json.loads(decoded_str)
            return {
                "label": get_final_label(d.get("add"), d.get("ps")),
                "type": "vmess", "server": d.get("add"), "port": int(d.get("port")),
                "uuid": d.get("id"), "alterId": 0, "cipher": "auto",
                "tls": str(d.get("tls","")).lower() in ["tls","true","1"],
                "skip-cert-verify": True, "udp": True, "raw_json": d
            }
        elif link.startswith(('ss://', 'trojan://', 'hy')):
            return {
                "label": get_final_label(u.hostname, u.fragment),
                "type": "other", "link": link
            }
    except: return None

def main():
    if not os.path.exists('nodes.txt'): return
    with open('nodes.txt', 'r', encoding='utf-8') as f:
        ls = f.read().splitlines()

    unique_links = list(dict.fromkeys([l.strip() for l in ls if l.strip() and not any(l.startswith(x) for x in ['import','def','git','#'])]))

    proxies = []
    region_map = defaultdict(list)
    final_links = []

    for l in unique_links:
        p = parse_link(l)
        if p:
            label = p.pop('label')
            idx = len(region_map[label]) + 1
            # 严格保留你最初的 ID 计数逻辑
            new_name = f"{label} {CHANNEL_MARK} {idx:02d}"
            p['name'] = new_name
            
            # 同步更新 Base64 订阅内容内部的名字
            if p.get('type') == "vmess":
                d = p.pop('raw_json')
                d['ps'] = new_name
                new_b = base64.b64encode(json.dumps(d).encode('utf-8')).decode('utf-8')
                final_links.append(f"vmess://{new_b}")
            else:
                base_part = l.split('#')[0]
                final_links.append(f"{base_part}#{urllib.parse.quote(new_name)}")

            proxies.append(p)
            region_map[label].append(p['name'])

    # 写入 index.html (Base64 订阅)
    subscription_b64 = base64.b64encode("\n".join(final_links).encode('utf-8')).decode('utf-8')
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(subscription_b64)

    print(f"✅ 处理完成！节点名称已统一，‘其它地区’已大幅减少。")

if __name__ == "__main__":
    main()
