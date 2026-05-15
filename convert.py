import base64, json, yaml, urllib.parse, os, re, requests, time
from collections import defaultdict

# --- 配置 ---
CHANNEL_MARK = "@zmxooo"
IP_CACHE = {}

# 预判逻辑 1：极其详尽的图标库，防止识别出国家却没图标
EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "日本": "🇯🇵", "韩国": "🇰🇷", "新加坡": "🇸🇬", 
    "美国": "🇺🇸", "英国": "🇬🇧", "德国": "🇩🇪", "法国": "🇫🇷", "俄罗斯": "🇷🇺", 
    "越南": "🇻🇳", "泰国": "🇹🇭", "菲律宾": "🇵🇭", "马来西亚": "🇲🇾", "印度": "🇮🇳", 
    "澳大利亚": "🇦🇺", "加拿大": "🇨🇦", "荷兰": "🇳🇱", "土耳其": "🇹🇷", "巴西": "🇧🇷"
}

def get_final_label(server, remarks):
    """
    预判识别：备注关键词 > 域名后缀 > IP API
    """
    rem_text = urllib.parse.unquote(str(remarks)).upper()
    server_low = server.lower()

    # 预判逻辑 2：强化正则库，解决“判断不准”
    rules = [
        ("香港", r"HK|HONGKONG|香港|HGC|HKT|PCCW"),
        ("台湾", r"TW|TAIWAN|台湾|CHT|彰化|台北"),
        ("日本", r"JP|JAPAN|日本|东京|大阪|東京|大阪"),
        ("韩国", r"KR|KOREA|韩国|首尔|首爾"),
        ("新加坡", r"SG|SINGAPORE|新加坡"),
        ("美国", r"US|USA|UNITED STATES|美国|洛杉矶|圣何塞"),
        ("英国", r"UK|GB|UNITED KINGDOM|英国|伦敦"),
        ("德国", r"DE|GERMANY|德国|法兰克福"),
        ("俄罗斯", r"RU|RUSSIA|俄罗斯|伯力|莫斯科"),
    ]
    
    # 优先从备注文字判断（最准）
    for name, pattern in rules:
        if re.search(pattern, rem_text):
            return f"{EMOJI_MAP.get(name, '🌍')} {name}"

    # 其次看域名后缀（极快）
    if server_low.endswith('.tw'): return f"{EMOJI_MAP['台湾']} 台湾"
    if server_low.endswith('.jp'): return f"{EMOJI_MAP['日本']} 日本"
    if server_low.endswith('.hk'): return f"{EMOJI_MAP['香港']} 香港"

    # 最后才动用 API（保底）
    if server in IP_CACHE: return IP_CACHE[server]
    try:
        time.sleep(0.15) # 预判：防止 API 封锁
        r = requests.get(f"http://ip-api.com/json/{server}?lang=zh-CN", timeout=3).json()
        if r.get("status") == "success":
            c = r.get("country", "")
            for key in EMOJI_MAP.keys():
                if key in c:
                    label = f"{EMOJI_MAP[key]} {key}"
                    IP_CACHE[server] = label
                    return label
            return f"🌍 {c}"
    except: pass
    return "🧿 其它地区"

# ... rebuild_node 保持全协议转换逻辑 ...

def main():
    if not os.path.exists('nodes.txt'): return
    
    with open('nodes.txt', 'r', encoding='utf-8', errors='ignore') as f:
        links = list(dict.fromkeys([l.strip() for l in f if "://" in l]))

    items = []
    for l in links:
        # 预判：提取 server 用于地区预分析
        host = ""
        try: host = urllib.parse.urlparse(l).hostname or ""
        except: pass
        label = get_final_label(host, l.split('#')[-1] if '#' in l else "")
        items.append({"label": label, "link": l})

    items.sort(key=lambda x: x["label"])
    
    final_subs, clash_proxies, counters = [], [], defaultdict(int)

    # 预判修复：Hy2/VLESS 字段补全，防止 Clash 报错
    for i in items:
        label = i["label"]
        counters[label] += 1
        name = f"{label} {counters[label]:02d} | {CHANNEL_MARK}"
        
        # 这里调用你之前的 rebuild_node，确保存入 clash_proxies
        # ... (此处省略重复的 rebuild_node 调用逻辑) ...
        
    # 写入保护逻辑：如果节点解析全失败，不覆盖旧文件
    if not clash_proxies:
        print("错误：未识别到有效节点，取消写入。")
        return

    # 生成带策略组的 config.yaml
    # ... (写入逻辑) ...
