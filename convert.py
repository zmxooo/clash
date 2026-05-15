import base64, json, yaml, urllib.parse, os, re

# 配置：只定义 Emoji，不搞复杂逻辑
CHANNEL_MARK = "zmxooo"
EMOJI_MAP = {"香港": "🇭🇰", "台湾": "🇹🇼", "美国": "🇺🇸", "日本": "🇯🇵", "韩国": "🇰🇷", "德国": "🇩🇪", "英国": "🇬🇧", "越南": "🇻🇳", "其它": "🌍"}

def main():
    if not os.path.exists('nodes.txt'): return
    with open('nodes.txt', 'r', encoding='utf-8') as f:
        links = [l.strip() for l in f if "://" in l]

    clash_proxies, base64_links = [], []
    region_counts = {k: 0 for k in EMOJI_MAP.keys()}

    for link in links:
        try:
            # 1. 直接抓取链接末尾 # 后的文字（这是你处理过的最准的信息）
            raw_remark = link.split('#')[1] if '#' in link else ""
            remark = urllib.parse.unquote(raw_remark) # 还原中文
            
            # 2. 简单的关键词匹配（只为了加个 Emoji 和 编号）
            region = "其它"
            for r in EMOJI_MAP.keys():
                if r in remark.lower() or r in link.lower(): # 包含中文或英文简称
                    region = r
                    break
            
            # 3. 统一命名：Emoji + 地区 + 编号
            region_counts[region] += 1
            new_name = f"{EMOJI_MAP[region]}{region} {CHANNEL_MARK}{region_counts[region]:02d}"

            # 4. 强制重写协议内容（彻底解决乱码问题）
            if link.startswith('vmess://'):
                # 提取服务器和配置，但 ps 字段强制改为 new_name
                b64_part = link[8:].split('#')[0]
                data = json.loads(base64.b64decode(b64_part + "==").decode('utf-8', 'ignore'))
                data["ps"] = new_name 
                # 关键：ensure_ascii=False 保证中文不乱码
                new_link = "vmess://" + base64.b64encode(json.dumps(data, ensure_ascii=False).encode('utf-8')).decode()
                server = data.get("add")
            else:
                new_link = f"{link.split('#')[0]}#{urllib.parse.quote(new_name)}"
                server = urllib.parse.urlparse(link).hostname

            base64_links.append(new_link)
            clash_proxies.append({"name": new_name, "server": server, "type": "ss"}) # 示例简化

        except: continue

    # 5. 最终写入
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(base64.b64encode("\n".join(base64_links).encode()).decode())
    
    with open('clash_config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump({"proxies": clash_proxies}, f, allow_unicode=True, sort_keys=False)

    print("处理完毕，备注已强制对齐！")

if __name__ == "__main__":
    main()
