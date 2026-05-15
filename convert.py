import base64, json, urllib.parse, re

# --- 增强版配置 ---
CHANNEL_MARK = "zmxooo"

# 这里的键名要和下面 REGION_KEYWORDS 的第一个元素对应
EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "美国": "🇺🇸", "日本": "🇯🇵", 
    "新加坡": "🇸🇬", "韩国": "🇰🇷", "德国": "🇩🇪", "英国": "🇬🇧",
    "越南": "🇻🇳", "其它": "🌍"
}

# 优先级：从上往下匹配。将容易误判的放在前面
REGION_KEYWORDS = [
    ("香港", r"hk|hongkong|香港|港|hgc|hkbn|pccw"),
    ("台湾", r"tw|taiwan|台湾|台灣|hinet|cht"),
    ("英国", r"uk|united kingdom|英国|英國|london"),
    ("德国", r"de|germany|德国|德國|frankfurt|fra"),
    ("韩国", r"kr|korea|韩国|韓國|seoul"),
    ("美国", r"us|united states|美国|美國|usa|lax|sjc"),
    ("日本", r"jp|japan|日本|東京|东京|tokyo"),
    ("越南", r"vn|vietnam|越南"),
]

def get_label_from_text(text):
    """直接从备注或地址文本中提取国家标签"""
    if not text: return None
    text = text.lower()
    for name, pattern in REGION_KEYWORDS:
        if re.search(pattern, text):
            return name
    return None

def get_final_label(server, remarks):
    """
    主要手段：解析备注。
    如果备注里有'英国'、'UK'等字眼，直接识别为英国。
    """
    # 1. 优先尝试从备注提取
    decoded_remarks = urllib.parse.unquote(str(remarks))
    label_name = get_label_from_text(decoded_remarks)
    
    # 2. 如果备注没识别到，尝试从服务器域名提取（例如含有 .hk, .tw）
    if not label_name:
        label_name = get_label_from_text(server)
        
    # 3. 兜底处理
    if not label_name:
        label_name = "其它"
        
    return f"{EMOJI_MAP.get(label_name, '🌍')}{label_name}"

def rebuild_node(link, region_counts):
    try:
        # --- VMESS 逻辑 ---
        if link.startswith('vmess://'):
            raw_b64 = link[8:].split('#')[0]
            # 补齐 base64 并解码
            missing_padding = len(raw_b64) % 4
            if missing_padding: raw_b64 += '=' * (4 - missing_padding)
            data = json.loads(base64.b64decode(raw_b64).decode('utf-8', 'ignore'))
            
            # 使用备注作为主要识别依据
            label = get_final_label(data.get("add", ""), data.get("ps", ""))
            
            # 生成新名字
            region_counts[label] += 1
            new_name = f"{label} {CHANNEL_MARK}{region_counts[label]:02d}"
            
            data["ps"] = new_name
            new_link = "vmess://" + base64.b64encode(json.dumps(data).encode()).decode()
            return label, new_link

        # --- 其他协议 (Hy2, SS, Trojan, Vless) ---
        u = urllib.parse.urlparse(link)
        # 获取原始备注（#后面的部分）
        raw_remarks = u.fragment
        label = get_final_label(u.hostname, raw_remarks)
        
        region_counts[label] += 1
        new_name = f"{label} {CHANNEL_MARK}{region_counts[label]:02d}"
        
        # 重新拼接链接，替换备注部分
        base_link = link.split('#')[0]
        new_link = f"{base_link}#{urllib.parse.quote(new_name)}"
        return label, new_link

    except Exception:
        return None, None

def main():
    # 假设 nodes.txt 存在
    input_file = 'nodes.txt'
    output_file = 'links_fixed.txt'
    
    with open(input_file, 'r', encoding='utf-8') as f:
        links = [l.strip() for l in f if "://" in l]
    
    region_counts = {f"{v}{k}": 0 for k, v in EMOJI_MAP.items()}
    new_links = []
    
    for l in links:
        label, new_l = rebuild_node(l, region_counts)
        if new_l:
            new_links.append(new_l)
            
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("\n".join(new_links))
    
    print(f"处理完成，结果已保存至 {output_file}")
    print("识别统计:", {k: v for k, v in region_counts.items() if v > 0})

if __name__ == "__main__":
    main()
