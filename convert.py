import base64, json, yaml, urllib.parse, os, re, requests, time
from collections import defaultdict

CHANNEL_MARK = "@zmxooo"

def get_final_label(server, remarks):
    text = urllib.parse.unquote(str(remarks)).lower().strip()
    # 1. 常用地区正则匹配（保持你原有的格式）
    meta = [
        ("🇭🇰 香港节点", r"hk|香港|hongkong"), 
        ("🇹🇼 台湾节点", r"tw|台湾|台灣|taiwan"),
        ("🇺🇸 美国节点", r"us|美国|美國|united states"), 
        ("🇬🇧 英国节点", r"gb|uk|英国|英國"),
        ("🇰🇷 韩国节点", r"kr|韩国|韓國|korea"), 
        ("🇯🇵 日本节点", r"jp|日本|japan"),
        ("🇸🇬 新加坡节点", r"sg|新加坡|singapore"), 
        ("🇻🇳 越南节点", r"vn|越南"),
        ("🇱🇹 立陶宛节点", r"lt|立陶宛"),
    ]
    for label, pattern in meta:
        if re.search(pattern, text): 
            return label
    
    # 2. 正则未命中，通过 IP-API 动态识别全球国家
    try:
        # 增加延时保护，避免查询 82.198.246.214 这种 IP 时被限流
        time.sleep(1.1) 
        r = requests.get(f"http://ip-api.com{server}?lang=zh-CN", timeout=3).json()
        if r.get("status") == "success":
            country_name = r.get("country")
            # 针对你原本定义的国家，保持格式对齐
            m = {
                "香港": "🇭🇰 香港节点", "台湾": "🇹🇼 台湾节点", "美国": "🇺🇸 美国节点",
                "英国": "🇬🇧 英国节点", "韩国": "🇰🇷 韩国节点", "日本": "🇯🇵 日本节点",
                "新加坡": "🇸🇬 新加坡节点", "越南": "🇻🇳 越南节点"
            }
            if country_name in m:
                return m[country_name]
            
            # --- 核心修改：如果是其它国家（如科威特），自动生成名称 ---
            return f"🌍 {country_name}节点"
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

    region_map = defaultdict(list)
    final_links = []

    for l in unique_links:
        p = parse_link(l)
        if p:
            label = p.pop('label')
            idx = len(region_map[label]) + 1
            # 严格遵循你最初的 ID 计数逻辑
            new_name = f"{label} {CHANNEL_MARK} {idx:02d}"
            
            # 同步更新 Base64 订阅内容内部的名字，解决 index.html 格式不统一
            if p.get('type') == "vmess":
                d = p.pop('raw_json')
                d['ps'] = new_name
                new_b = base64.b64encode(json.dumps(d).encode('utf-8')).decode('utf-8')
                final_links.append(f"vmess://{new_b}")
            else:
                base_part = l.split('#')[0]
                final_links.append(f"{base_part}#{urllib.parse.quote(new_name)}")

            region_map[label].append(new_name)

    # 重新生成 Base64 订阅字符串并写入 index.html
    subscription_text = "\n".join(final_links)
    subscription_b64 = base64.b64encode(subscription_text.encode('utf-8')).decode('utf-8')
    
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(subscription_b64)

    print(f"✅ 处理完成！已动态识别全球国家（如科威特），并统一编号。")

if __name__ == "__main__":
    main()
