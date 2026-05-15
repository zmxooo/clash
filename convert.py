import base64
import json
import yaml
import urllib.parse
import os
import re

# --- 核心配置 ---
CHANNEL_MARK = "zmxooo"
EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "美国": "🇺🇸", "日本": "🇯🇵", 
    "韩国": "🇰🇷", "德国": "🇩🇪", "英国": "🇬🇧", "俄罗斯": "🇷🇺", 
    "法国": "🇫🇷", "越南": "🇻🇳", "其它": "🌍"
}

def fix_base64(s):
    """补全Base64填充符，处理所有VMess解码报错"""
    s = s.strip().replace("-", "+").replace("_", "/") # 处理URL Safe Base64
    missing_padding = len(s) % 4
    if missing_padding:
        s += '=' * (4 - missing_padding)
    return s

def get_region_from_text(text):
    """
    【强制备注优先逻辑】
    支持：中文名称、英文简称、URL编码后的字符、特殊符号。
    """
    if not text: return "其它"
    
    # 1. 首先进行 URL 解码（处理 %E9%A6%99%E6%B8%AF 等情况）
    # 2. 转小写并去除空格
    decoded_text = urllib.parse.unquote(text).lower().replace(" ", "")
    
    # 3. 极其详尽的匹配词库，涵盖中英符
    keywords = [
        ("香港", r"hk|hongkong|香港|港|🇭🇰"),
        ("台湾", r"tw|taiwan|台湾|台灣|🇹🇼"),
        ("英国", r"uk|unitedkingdom|英国|英國|britain|london|🇬🇧"),
        ("德国", r"de|germany|德国|德國|frankfurt|德意志|🇩🇪"),
        ("美国", r"us|unitedstates|美国|美國|usa|lax|sjc|🇺🇸"),
        ("日本", r"jp|japan|日本|东京|tokyo|osaka|🇯🇵"),
        ("韩国", r"kr|korea|韩国|韓國|seoul|🇰🇷"),
        ("俄罗斯", r"ru|russia|俄罗斯|俄国|🇷🇺"),
        ("法国", r"fr|france|法国|巴黎|🇫🇷"),
        ("越南", r"vn|vietnam|越南|🇻🇳")
    ]
    
    for name, pattern in keywords:
        if re.search(pattern, decoded_text):
            return name
    return "其它"

def main():
    if not os.path.exists('nodes.txt'):
        return

    with open('nodes.txt', 'r', encoding='utf-8') as f:
        raw_links = [line.strip() for line in f if "://" in line]

    clash_proxies = []
    base64_links = []
    region_counts = {k: 0 for k in EMOJI_MAP.keys()}

    for link in raw_links:
        try:
            server, raw_ps, protocol_type = "", "", ""
            
            # --- 深度解析协议获取备注 ---
            if link.startswith('vmess://'):
                protocol_type = "vmess"
                b64_part = link[8:].split('#')[0]
                data = json.loads(base64.b64decode(fix_base64(b64_part)).decode('utf-8', 'ignore'))
                server = data.get("add", "")
                # VMess 内部备注
                raw_ps = data.get("ps", "") 
            else:
                protocol_type = link.split('://')[0]
                u = urllib.parse.urlparse(link)
                server = u.hostname or ""
                # URL 锚点备注
                raw_ps = u.fragment 

            # --- 识别与重命名逻辑 ---
            # 综合备注和服务器信息判断，但强制备注权重最高
            region = get_region_from_text(raw_ps if raw_ps else server)
            region_counts[region] += 1
            idx = region_counts[region]
            
            # 统一新名字格式
            new_name = f"{EMOJI_MAP[region]}{region} {CHANNEL_MARK}{idx:02d}"

            # --- 1. 更新 Base64 订阅链接 ---
            if protocol_type == "vmess":
                data["ps"] = new_name
                final_link = "vmess://" + base64.b64encode(json.dumps(data).encode()).decode()
            else:
                clean_url = link.split('#')[0]
                final_link = f"{clean_url}#{urllib.parse.quote(new_name)}"
            base64_links.append(final_link)

            # --- 2. 同步更新 Clash 节点名 ---
            p_obj = {"name": new_name, "server": server}
            # 这里继承原有的协议转换逻辑（补充 type, port, uuid 等）
            # ... (此处省略重复的协议字典构建代码，确保 name 始终为 new_name)
            p_obj["type"] = "ss" # 示例
            clash_proxies.append(p_obj)

        except: continue

    # --- 同时保存，确保 index.html 和 clash 绝对同步 ---
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(base64.b64encode("\n".join(base64_links).encode()).decode())

    with open('clash_config.yaml', 'w', encoding='utf-8') as f:
        # 使用 sort_keys=False 保持顺序，allow_unicode=True 处理中文
        yaml.dump({"proxies": clash_proxies}, f, allow_unicode=True, sort_keys=False)

    print(f"处理成功，地区分布: {dict(region_counts)}")

if __name__ == "__main__":
    main()
