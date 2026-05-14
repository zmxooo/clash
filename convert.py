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
    "日本": "🇯🇵", "新加坡": "🇸🇬", "越南": "🇻🇳", "德国": "🇩🇪", "法国": "🇫🇷"
}

def fix_base64(s):
    """保持原有逻辑：修正补齐 Base64，确保解码不报错"""
    if not s: return ""
    s = "".join(s.split()) 
    return s + '=' * (-len(s) % 4)

def get_final_label(server, remarks):
    """地理位置识别：优先正则，其次 IP 库"""
    text = urllib.parse.unquote(str(remarks)).lower().strip()
    meta = [
        ("香港", r"hk|香港|hongkong"), ("台湾", r"tw|台湾|台灣|taiwan"), 
        ("美国", r"us|美国|美國|united states"), ("日本", r"jp|日本|japan"),
        ("新加坡", r"sg|新加坡|singapore")
    ]
    for name, pattern in meta:
        if re.search(pattern, text): 
            return f"{EMOJI_MAP.get(name, '🌍')} {name}"
    
    if server in IP_CACHE: return IP_CACHE[server]
    try:
        time.sleep(0.1) # 频率限制，防止被 ip-api 封禁
        response = requests.get(f"http://ip-api.com/json/{server}?lang=zh-CN", timeout=5).json()
        if response.get("status") == "success":
            country = response.get("country")
            label = f"{EMOJI_MAP.get(country, '🌍')} {country}"
            IP_CACHE[server] = label
            return label
    except: pass
    return "🧿 其它地区"

def rebuild_node(link, new_name):
    """重构节点核心：确保生成的字典严格符合 Clash 语法规范"""
    try:
        # --- VMess 协议重构 ---
        if link.startswith('vmess://'):
            b64_part = link[8:].split('#')[0]
            decoded_bytes = base64.b64decode(fix_base64(b64_part))
            d = json.loads(decoded_bytes.decode('utf-8', 'ignore'))
            label = get_final_label(d.get("add"), d.get("ps", ""))
            
            # 1. 构造标准 VMess 字典（用于返回通用链接）
            std_vmess = {
                "v": "2", "ps": new_name, "add": str(d.get("add", "")).strip(),
                "port": str(d.get("port", "443")), "id": str(d.get("id", "")).strip(),
                "aid": str(d.get("aid", "0")), "net": d.get("net", "tcp"),
                "type": d.get("type", "none"), "host": d.get("host", ""),
                "path": d.get("path", ""), "tls": d.get("tls", "")
            }
            # 2. 构造 Clash 专用字典（严格校验类型）
            proxy = {
                "name": new_name,
                "type": "vmess",
                "server": std_vmess["add"],
                "port": int(std_vmess["port"]), # 必须是 int
                "uuid": std_vmess["id"],
                "alterId": int(std_vmess["aid"]), # 必须是 int
                "cipher": "auto",
                "tls": True if str(std_vmess["tls"]).lower() in ["tls", "1", "true"] else False, # 必须是 bool
                "network": std_vmess["net"]
            }
            if proxy["network"] == "ws":
                proxy["ws-opts"] = {"path": std_vmess["path"], "headers": {"Host": std_vmess["host"]}}
            
            new_b64 = base64.b64encode(json.dumps(std_vmess).encode('utf-8')).decode('utf-8')
            return label, proxy, f"vmess://{new_b64}"

        # --- Shadowsocks (ss) 协议重构 ---
        elif link.startswith('ss://'):
            base_part = link[5:].split('#')[0]
            old_remarks = urllib.parse.unquote(link.split('#')[1]) if '#' in link else ""
            if "@" in base_part:
                user_info, server_info = base_part.split("@")
                decoded_user = base64.b64decode(fix_base64(user_info)).decode('utf-8', 'ignore')
                method, password = decoded_user.split(":", 1)
                server, port = server_info.split(":", 1)
                label = get_final_label(server, old_remarks)
                proxy = {"name": new_name, "type": "ss", "server": server, "port": int(port), "cipher": method, "password": password}
                return label, proxy, f"ss://{user_info}@{server}:{port}#{urllib.parse.quote(new_name)}"
        
        # --- 无法识别的协议处理 ---
        # 返回 type: "other" 以触发 main 函数的过滤逻辑，防止 Clash 报错
        u = urllib.parse.urlparse(link)
        label = get_final_label(u.hostname, "")
        return label, {"type": "other"}, link

    except Exception:
        return None, None, None

def main():
    if not os.path.exists('nodes.txt'):
        print("❌ 未找到 nodes.txt，请创建并放入原始链接。")
        return

    with open('nodes.txt', 'r', encoding='utf-8') as f:
        # 去重并清洗无效行
        raw_links = list(set([line.strip() for line in f if "://" in line]))

    clash_proxies = []
    processed_links = []
    country_stats = defaultdict(int)

    print(f"🚀 开始处理 {len(raw_links)} 个节点...")

    for link in raw_links:
        # 第一次模拟重构：获取地理标签
        label_seed, _, _ = rebuild_node(link, "TEMP")
        if not label_seed: continue
        
        # 生成规范化的节点名称
        country_stats[label_seed] += 1
        final_name = f"{label_seed} {country_stats[label_seed]:02d} {CHANNEL_MARK}"
        
        # 第二次正式重构
        label, proxy, final_link = rebuild_node(link, final_name)
        
        if final_link:
            processed_links.append(final_link)
            # 【关键防御】仅允许 Clash 认识的类型进入 YAML
            if proxy and proxy.get("type") not in [None, "other"]:
                clash_proxies.append(proxy)
            else:
                print(f"⚠️  跳过 Clash 不支持的协议: {final_name}")

    # 1. 导出通用 Base64 订阅文本
    with open('nodes_fixed.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(processed_links))

    # 2. 导出完整 Clash 配置文件
    full_config = {
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
        yaml.dump(full_config, f, allow_unicode=True, sort_keys=False)

    print("-" * 30)
    print(f"✅ 处理完成！")
    print(f"📝 节点总数: {len(processed_links)}")
    print(f"🛡️  Clash 可用节点: {len(clash_proxies)}")
    print(f"📁 结果已存入: nodes_fixed.txt 和 clash_config.yaml")

if __name__ == "__main__":
    main()
