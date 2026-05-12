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

def get_final_label(server, remarks):
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
    针对 V2RayTun / V2Box 优化的重命名逻辑
    """
    try:
        link = link.strip()
        if not link: return None
        
        # 统一去除重复的前缀
        if link.startswith('vmess://vmess://'):
            link = link[8:]

        u = urllib.parse.urlparse(link)
        raw_remarks = urllib.parse.unquote(u.fragment) if u.fragment else ""

        if link.startswith('vmess://'):
            # 1. Base64 补位并解码
            b64_str = link[8:].split('#')[0]
            b64_str += '=' * (-len(b64_str) % 4)
            d = json.loads(base64.b64decode(b64_str).decode('utf-8'))
            
            # 2. 识别地区并改写 JSON
            city, emoji = get_final_label(d.get("add"), d.get("ps") or raw_remarks)
            region_counts[city] += 1
            d["ps"] = f"{emoji} {city} {CHANNEL_MARK} {region_counts[city]:02d}"
            
            # 3. 重新编码 VMess (关键：剔除所有空白符)
            new_json_b64 = base64.b64encode(json.dumps(d).encode('utf-8')).decode('utf-8')
            new_json_b64 = re.sub(r'[\s\n\r]+', '', new_json_b64)
            return f"vmess://{new_json_b64}"

        elif link.startswith(('ss://', 'trojan://', 'hy2://', 'hysteria2://')):
            # 处理 SS/Trojan 的备注替换
            city, emoji = get_region_info_from_host(u.hostname, raw_remarks)
            region_counts[city] += 1
            # 备注需要进行 URL 编码
            new_name = urllib.parse.quote(f"{emoji} {city} {CHANNEL_MARK} {region_counts[city]:02d}")
            
            # 剥离旧备注并重组
            base_part = link.split('#')[0]
            return f"{base_part}#{new_name}"
            
    except:
        return link
    return link

def get_region_info_from_host(host, remarks):
    # 辅助函数：由于 SS 没有 JSON，从 host 或 fragment 拿地区
    return get_final_label(host, remarks)

def main():
    if not os.path.exists('nodes.txt'):
        return

    with open('nodes.txt', 'r', encoding='utf-8') as f:
        ls = [l.strip() for l in f.read().splitlines() if l.strip()]

    # 1. 基础去重（方案二）
    unique_links = list(dict.fromkeys(ls))
    
    # 2. 核心：重命名所有节点内部名称
    region_counts = defaultdict(int)
    renamed_links = []
    for l in unique_links:
        new_node = rename_node(l, region_counts)
        if new_node:
            renamed_links.append(new_node)

    # 3. 生成 Base64 订阅内容 (这是放入 index.html 的部分)
    # V2RayTun 要求链接间必须是换行符，且整体 Base64 没有任何格式干扰
    nodes_text = "\n".join(renamed_links)
    final_b64 = base64.b64encode(nodes_text.encode('utf-8')).decode('utf-8')
    final_b64 = re.sub(r'[\s\n\r]+', '', final_b64)

    # 4. 写入 index.html (模拟你的输出逻辑)
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(final_b64)

    print(f"✅ 处理完成！已为 V2Box / V2RayTun 生成名称统一的订阅。")

if __name__ == "__main__":
    main()
