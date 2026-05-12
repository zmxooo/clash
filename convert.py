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
    """提取地区名称和图标"""
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
    
    # 简单的 IP API 备份
    try:
        r = requests.get(f"http://ip-api.com{server}?lang=zh-CN", timeout=2).json()
        if r.get("status") == "success":
            c = r.get("country")
            m = {"香港":("香港","🇭🇰"), "美国":("美国","🇺🇸"), "日本":("日本","🇯🇵")}
            return m.get(c, (c, "🌍"))
    except: pass
    return "其它", "🧿"

def rename_node(link, region_counts):
    """
    最关键的一步：解开链接协议，强制修改其内部备注名，再封回去
    这样 base64 订阅里的名字才会统一
    """
    try:
        link = link.strip()
        u = urllib.parse.urlparse(link)
        
        if link.startswith('vmess://'):
            # 处理 VMess 内部名称
            b64_part = link[8:].split('#')[0]
            b64_part += '=' * (-len(b64_part) % 4)
            d = json.loads(base64.b64decode(b64_part).decode('utf-8'))
            
            city, emoji = get_region_info(d.get("add"), d.get("ps") or u.fragment)
            region_counts[city] += 1
            # 强制统一 ps 字段
            d["ps"] = f"{emoji} {city} {CHANNEL_MARK} {region_counts[city]:02d}"
            
            new_json = json.dumps(d).encode('utf-8')
            return "vmess://" + base64.b64encode(new_json).decode('utf-8')

        elif link.startswith(('ss://', 'trojan://', 'hy2://', 'hysteria2://')):
            # 处理 SS/Trojan/Hy2 的备注（# 后面部分）
            city, emoji = get_region_info(u.hostname, u.fragment)
            region_counts[city] += 1
            new_name = urllib.parse.quote(f"{emoji} {city} {CHANNEL_MARK} {region_counts[city]:02d}")
            
            # 移除旧备注，拼上新备注
            base_url = link.split('#')[0]
            return f"{base_url}#{new_name}"
            
    except:
        return link # 出错则返回原样
    return link

def main():
    if not os.path.exists('nodes.txt'):
        return

    with open('nodes.txt', 'r', encoding='utf-8') as f:
        ls = [l.strip() for l in f.read().splitlines() if l.strip()]

    # 1. 基础去重（方案二）
    unique_links = list(dict.fromkeys(ls))
    
    # 2. 统一所有节点的内部名称
    region_counts = defaultdict(int)
    final_links = []
    for l in unique_links:
        renamed = rename_node(l, region_counts)
        if renamed:
            final_links.append(renamed)

    # 3. 生成 index.html 里的那串 Base64 订阅
    # 把所有改名后的链接拼起来，整体转 Base64
    nodes_combined = "\n".join(final_links)
    b64_subscription = base64.b64encode(nodes_combined.encode('utf-8')).decode('utf-8')

    # 4. 写入 index.html (这里模拟你的写入逻辑)
    html_content = f"<html><body>{b64_subscription}</body></html>"
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"✅ 处理完成！index.html 里的 Base64 节点名称已全部统一。")

if __name__ == "__main__":
    main()
