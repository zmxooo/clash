import base64
import json
import yaml
import urllib.parse
import os
import re
import requests
import time
from collections import defaultdict

CHANNEL_MARK = "@zmxooo"

def get_region_info(server, remarks):
    text = urllib.parse.unquote(str(remarks)).lower().strip()
    meta = [
        ("香港", "🇭🇰", r"hk|香港"), 
        ("台湾", "🇹🇼", r"tw|台湾|台灣"),
        ("美国", "🇺🇸", r"us|美国|美國"), 
        ("英国", "🇬🇧", r"gb|uk|英国|英國"),
        ("韩国", "🇰🇷", r"kr|韩国|韓國"), 
        ("日本", "🇯🇵", r"jp|日本"),
        ("新加坡", "🇸🇬", r"sg|新加坡")
    ]
    for label, emoji, pattern in meta:
        if re.search(pattern, text): 
            return label, emoji
    return "其它", "🌍"

def rename_node(link, region_counts):
    """
    深度重命名链接内部备注，解决 Base64 订阅名称不统一问题
    """
    try:
        link = link.strip()
        if not link: return None
        
        # 提取原有的备注（# 之后的部分）
        u = urllib.parse.urlparse(link)
        raw_remarks = urllib.parse.unquote(u.fragment) if u.fragment else ""

        if link.startswith('vmess://'):
            # 1. 提取 VMess JSON 部分
            b64_data = link[8:].split('#')[0]
            b64_data += '=' * (-len(b64_data) % 4)
            d = json.loads(base64.b64decode(b64_data).decode('utf-8'))
            
            # 2. 识别并统计
            city, emoji = get_region_info(d.get("add"), d.get("ps") or raw_remarks)
            region_counts[city] += 1
            # 3. 强制改写名称
            d["ps"] = f"{emoji} {city} {CHANNEL_MARK} {region_counts[city]:02d}"
            
            # 4. 重新编码（注意：一定要去掉换行符）
            new_json_b64 = base64.b64encode(json.dumps(d).encode('utf-8')).decode('utf-8').replace('\n', '').replace('\r', '')
            return f"vmess://{new_json_b64}"

        elif link.startswith(('ss://', 'trojan://', 'hy2://', 'hysteria2://')):
            # 处理 SS/Trojan/Hy2 的备注替换
            city, emoji = get_region_info(u.hostname, raw_remarks)
            region_counts[city] += 1
            new_name = urllib.parse.quote(f"{emoji} {city} {CHANNEL_MARK} {region_counts[city]:02d}")
            
            # 找到最后一个 # 的位置并替换
            base_part = link.split('#')[0]
            return f"{base_part}#{new_name}"
            
    except:
        return link # 万一出错保留原链接，防止订阅变为空
    return link

def main():
    if not os.path.exists('nodes.txt'):
        return

    with open('nodes.txt', 'r', encoding='utf-8') as f:
        ls = [l.strip() for l in f.read().splitlines() if l.strip()]

    # 1. 基础去重
    unique_links = list(dict.fromkeys(ls))
    
    # 2. 统一所有链接内部的名称
    region_counts = defaultdict(int)
    renamed_links = []
    for l in unique_links:
        new_l = rename_node(l, region_counts)
        if new_l:
            renamed_links.append(new_l)

    # 3. 生成 Base64 订阅字符串（用于 index.html）
    # 链接之间必须用换行符连接，且整体编码不能有换行
    combined_text = "\n".join(renamed_links)
    final_b64 = base64.b64encode(combined_text.encode('utf-8')).decode('utf-8').replace('\n', '').replace('\r', '')

    # 4. 写入 index.html (请根据你实际的 HTML 结构调整)
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(final_b64)

    print(f"✅ 处理完成！已生成统一名称的 Base64 订阅。")

if __name__ == "__main__":
    main()
