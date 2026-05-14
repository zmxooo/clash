import base64
import json
import yaml
import urllib.parse
import os
import re
import requests
import time
from collections import defaultdict

# --- 配置区 ---
CHANNEL_MARK = "@zmxooo"
TEST_URL = "http://www.gstatic.com/generate_204"
IP_CACHE = {}

# 常用图标映射
EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "美国": "🇺🇸", "英国": "🇬🇧", "韩国": "🇰🇷", 
    "日本": "🇯🇵", "新加坡": "🇸🇬", "越南": "🇻🇳", "立陶宛": "🇱🇹", "科威特": "🇰🇼",
    "德国": "🇩🇪", "法国": "🇫🇷", "俄罗斯": "🇷🇺", "中国": "🇨🇳", "加拿大": "🇨🇦"
}

def get_final_label(server, remarks):
    text = urllib.parse.unquote(str(remarks)).lower().strip()
    meta = [
        ("香港", r"hk|香港|hongkong"), ("台湾", r"tw|台湾|台灣|taiwan"), 
        ("美国", r"us|美国|美國|united states"), ("英国", r"gb|uk|英国|英國"), 
        ("韩国", r"kr|韩国|韓國|korea"), ("日本", r"jp|日本|japan"),
        ("新加坡", r"sg|新加坡|singapore"), ("越南", r"vn|越南|vietnam"), 
        ("科威特", r"kw|科威特|kuwait"), ("德国", r"de|德国|germany"),
        ("立陶宛", r"lt|立陶宛|lithuania")
    ]
    for name, pattern in meta:
        if re.search(pattern, text): 
            return f"{EMOJI_MAP.get(name, '🌍')} {name}"
    
    if server in IP_CACHE: return IP_CACHE[server]

    try:
        time.sleep(0.1) 
        response = requests.get(f"http://ip-api.com/json/{server}?lang=zh-CN", timeout=5).json()
        if response.get("status") == "success":
            country = response.get("country")
            label = f"{EMOJI_MAP.get(country, '🌍')} {country}"
            IP_CACHE[server] = label
            return label
    except:
        pass
    return "🧿 其它地区"

def fix_base64(s):
    if not s: return ""
    s = "".join(s.split())
    return s + '=' * (-len(s) % 4)

def rebuild_node(link, new_name):
    """
    重构节点：增加对不同协议转换至 Clash 字典的支持
    """
    try:
        # --- VMess 协议重构 ---
        if link.startswith('vmess://'):
            b64_part = link[8:].split('#')[0]
            decoded_bytes = base64.b64decode(fix_base64(b64_part))
            d = json.loads(decoded_bytes.decode('utf-8', 'ignore'))
            
            label = get_final_label(d.get("add"), d.get("ps", ""))
            
            # 标准 VMess JSON 用于通用链接
            std_vmess = {
                "v": "2", "ps": new_name, "add": str(d.get("add", "")).strip(),
                "port": str(d.get("port", "443")), "id": str(d.get("id", "")).strip(),
                "aid": str(d.get("aid", "0")), "scy": d.get("scy", "auto"),
                "net": d.get("net", "tcp"), "type": d.get("type", "none"),
                "host": d.get("host", ""), "path": d.get("path", ""),
                "tls": d.get("tls", ""), "sni": d.get("sni", ""), "alpn": d.get("alpn", "")
            }
            
            # Clash 节点对象
            proxy = {
                "name": new_name,
                "type": "vmess",
                "server": std_vmess["add"],
                "port": int(std_vmess["port"]),
                "uuid": std_vmess["id"],
                "alterId": int(std_vmess["aid"]),
                "cipher": "auto",
                "tls": True if str(std_vmess["tls"]).lower() in ["tls", "1", "true"] else False,
                "skip-cert-verify": True,
                "network": std_vmess["net"]
            }
            if proxy["network"] == "ws":
                proxy["ws-opts"] = {"path": std_vmess["path"], "headers": {"Host": std_vmess["host"]}}
            
            new_json_str = json.dumps(std_vmess, separators=(',', ':'), ensure_ascii=False)
            new_b64 = base64.b64encode(new_json_str.encode('utf-8')).decode('utf-8')
            return label, proxy, f"vmess://{new_b64}"

        # --- Shadowsocks (ss) 协议重构 ---
        elif link.startswith('ss://'):
            # 处理 ss://method:password@host:port#name 格式
            base_part = link[5:].split('#')[0]
            old_remarks = urllib.parse.unquote(link.split('#')[1]) if '#' in link else ""
            
            if "@" in base_part:
                user_info, server_info = base_part.split("@")
                # 解码用户信息 (method:password)
                decoded_user = base64.b64decode(fix_base64(user_info)).decode('utf-8')
                method, password = decoded_user.split(":")
                server, port = server_info.split(":")
            else:
                # 处理部分 base64 整个链接的情况
                decoded_all = base64.b64decode(fix_base64(base_part)).decode('utf-8')
                # 递归处理解码后的 ss 链接
                return rebuild_node(f"ss://{decoded_all}#{old_remarks}", new_name)

            label = get_final_label(server, old_remarks)
            proxy = {
                "name": new_name,
                "type": "ss",
                "server": server,
                "port": int(port),
                "cipher": method,
                "password": password
            }
            safe_name = urllib.parse.quote(new_name)
            return label, proxy, f"ss://{user_info}@{server}:{port}#{safe_name}"

        # --- 其他协议 (暂作为通用链接处理，Clash 需根据需求进一步细化解析) ---
        elif "://" in link:
            u = urllib.parse.urlparse(link)
            base_url = link.split('#')[0].strip()
            old_remarks = urllib.parse.unquote(link.split('#')[1]) if '#' in link else ""
            label = get_final_label(u.hostname, old_remarks)
            
            # 由于 VLESS/Hysteria2 字段复杂，此处仅保持链接重构，Clash 配置跳过
            safe_name = urllib.parse.quote(new_name)
            return label, None, f"{base_url}#{safe_name}"

    except Exception:
        return None, None, None

def main():
    if not os.path.exists('nodes.txt'):
        print("❌ 未找到 nodes.txt")
        return

    with open('nodes.txt', 'r', encoding='utf-8') as f:
        raw_links = list(set([line.strip() for line in f if "://" in line]))

    clash_proxies = []
    processed_links = []
    country_stats = defaultdict(int)

    print(f"开始处理 {len(raw_links)} 个节点...")

    for link in raw_links:
        # 预解析获取国家
        temp_label, _, _ = rebuild_node(link, "TEMP")
        if not temp_label: continue
        
        country_stats[temp_label] += 1
        final_name = f"{temp_label} {country_stats[temp_label]:02d} {CHANNEL_MARK}"
        
        # 正式重构
        label, proxy, final_link = rebuild_node(link, final_name)
        if final_link:
            processed_links.append(final_link)
            if proxy: # 只有成功转换为 Clash 字典的才加入
                clash_proxies.append(proxy)

    # --- 1. 生成通用订阅列表 ---
    with open('nodes_fixed.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(processed_links))

    # --- 2. 生成完整的 Clash 配置文件 ---
    clash_config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "proxies": clash_proxies,
        "proxy-groups": [
            {
                "name": "🔰 节点选择",
                "type": "select",
                "proxies": ["🚀 自动选择", "DIRECT"] + [p["name"] for p in clash_proxies]
            },
            {
                "name": "🚀 自动选择",
                "type": "url-test",
                "proxies": [p["name"] for p in clash_proxies],
                "url": TEST_URL,
                "interval": 300
            }
        ],
        "rules": [
            "DOMAIN-SUFFIX,google.com,🔰 节点选择",
            "GEOIP,CN,DIRECT",
            "MATCH,🔰 节点选择"
        ]
    }

    with open('clash_config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)

    print(f"✅ 处理完成！通用列表已存入 nodes_fixed.txt，Clash 配置已存入 clash_config.yaml")

if __name__ == "__main__":
    main()
