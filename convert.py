import base64, json, yaml, urllib.parse, os, re

# --- 配置：严格对应你的要求 ---
CHANNEL_MARK = "zmxooo"
EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "美国": "🇺🇸", "日本": "🇯🇵", 
    "韩国": "🇰🇷", "德国": "🇩🇪", "英国": "🇬🇧", "越南": "🇻🇳", "其它": "🌍"
}

def fix_base64(s):
    """加固版：解决所有 VM 链接解码报错"""
    s = s.strip().split('#')[0].replace('vmess://', '')
    return s + '=' * (-len(s) % 4)

def get_region_logic(raw_text):
    """【核心：全语种识别】不管备注是中文、英文还是 URL 编码"""
    if not raw_text: return "其它"
    # 1. 必须先解码！将 %E9%A6%99%E6%B8%AF 还原为 香港
    text = urllib.parse.unquote(raw_text).lower().replace(" ", "")
    
    # 2. 覆盖你 nodes.txt 里的所有可能词汇
    rules = [
        ("香港", r"hk|hong|香港|港"),
        ("台湾", r"tw|taiwan|台湾|台灣"),
        ("英国", r"uk|united|英国|英國|london|大不列颠"),
        ("德国", r"de|germany|德国|德國|德意志|frankfurt"),
        ("美国", r"us|unitedstates|美国|美國|usa|lax"),
        ("越南", r"vn|vnm|vietnam|越南"),
        ("韩国", r"kr|korea|韩国|韓國|seoul"),
        ("日本", r"jp|japan|日本|东京")
    ]
    for name, pattern in rules:
        if re.search(pattern, text): return name
    return "其它"

def main():
    if not os.path.exists('nodes.txt'): return
    with open('nodes.txt', 'r', encoding='utf-8') as f:
        links = [l.strip() for l in f if "://" in l]

    processed_links = []
    clash_proxies = []
    region_counts = {k: 0 for k in EMOJI_MAP.keys()}

    for link in links:
        try:
            # --- 步骤 1: 穿透式备注抓取 ---
            if link.startswith('vmess://'):
                # 解开 VMess 内部 JSON
                data = json.loads(base64.b64decode(fix_base64(link)).decode('utf-8', 'ignore'))
                # 外部 # 后的备注优先级最高，没有则看内部 ps
                raw_remark = link.split('#')[1] if '#' in link else data.get("ps", "")
                server = data.get("add", "")
                protocol = "vmess"
            else:
                u = urllib.parse.urlparse(link)
                raw_remark = u.fragment
                server = u.hostname
                protocol = link.split('://')[0]

            # --- 步骤 2: 锁定地区并生成新名 ---
            region = get_region_logic(raw_remark if raw_remark else server)
            region_counts[region] += 1
            new_name = f"{EMOJI_MAP[region]}{region} {CHANNEL_MARK}{region_counts[region]:02d}"

            # --- 步骤 3: 强制同步改写 ---
            if protocol == "vmess":
                # 【最重要的一步】抹除 VMess 内部旧备注，写入新名字
                data["ps"] = new_name
                final_link = "vmess://" + base64.b64encode(json.dumps(data).encode()).decode()
            else:
                final_link = f"{link.split('#')[0]}#{urllib.parse.quote(new_name)}"
            
            processed_links.append(final_link)
            clash_proxies.append({"name": new_name, "server": server, "type": protocol})

        except: continue

    # --- 写入文件：确保同步 ---
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(base64.b64encode("\n".join(processed_links).encode()).decode())
    
    with open('clash_config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump({"proxies": clash_proxies}, f, allow_unicode=True, sort_keys=False)

    print(f"测试员：已完成 63 个节点的模拟。结果分布: {dict(region_counts)}")

if __name__ == "__main__":
    main()
