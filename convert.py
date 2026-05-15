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
TEST_URL = "http://gstatic.com"
CACHE_FILE = "ip_cache.json"
IP_CACHE = {}

# 常用图标映射
EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "美国": "🇺🇸", "英国": "🇬🇧", "韩国": "🇰🇷", 
    "日本": "🇯🇵", "新加坡": "🇸🇬", "越南": "🇻🇳", "立陶宛": "🇱🇹", "科威特": "🇰🇼",
    "德国": "🇩🇪", "法国": "🇫🇷", "俄罗斯": "🇷🇺", "中国": "🇨🇳", "加拿大": "🇨🇦"
}

def load_cache():
    """加载本地 IP 缓存，优化同步速度"""
    global IP_CACHE
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                IP_CACHE = json.load(f)
        except Exception:
            IP_CACHE = {}

def save_cache():
    """保存 IP 缓存到本地"""
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(IP_CACHE, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def get_final_label(server, remarks):
    """
    国家识别逻辑：优先正则匹配备注，其次查询 IP 库（带本地缓存优化）
    """
    if not server:
        return "🧿 其它地区"
        
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
    
    # 优先读取内存/本地文件缓存，避免重复请求 API 导致同步卡顿或被封 IP
    if server in IP_CACHE: 
        return IP_CACHE[server]

    # 若为纯 IP 或无法从域名猜测，则请求外部 API
    try:
        time.sleep(0.1)  # 限制频率
        response = requests.get(f"http://ip-api.com{server}?lang=zh-CN", timeout=5).json()
        if response.get("status") == "success":
            country = response.get("country")
            label = f"{EMOJI_MAP.get(country, '🌍')} {country}"
            IP_CACHE[server] = label
            return label
    except Exception:
        pass
    return "🧿 其它地区"

def fix_base64(s):
    """
    修正 Base64 格式：去除空白符并自动补齐等号
    """
    if not s: return ""
    s = "".join(s.split())
    return s + '=' * (-len(s) % 4)

def rebuild_node(link, new_name):
    """
    重构节点：剥离一切原始信息，强制使用标准格式和新命名
    """
    try:
        # --- VMess 协议重构 ---
        if link.startswith('vmess://'):
            b64_part = link[8:].split('#')[0]
            decoded_bytes = base64.b64decode(fix_base64(b64_part))
            d = json.loads(decoded_bytes.decode('utf-8', 'ignore'))
            
            label = get_final_label(d.get("add"), d.get("ps", ""))
            
            std_vmess = {
                "v": "2", "ps": new_name, "add": str(d.get("add", "")).strip(),
                "port": str(d.get("port", "443")), "id": str(d.get("id", "")).strip(),
                "aid": str(d.get("aid", "0")), "scy": d.get("scy", "auto"),
                "net": d.get("net", "tcp"), "type": d.get("type", "none"),
                "host": d.get("host", ""), "path": d.get("path", ""),
                "tls": d.get("tls", ""), "sni": d.get("sni", ""), "alpn": d.get("alpn", "")
            }
            
            proxy = {
                "name": new_name, "type": "vmess", "server": std_vmess["add"],
                "port": int(std_vmess["port"]), "uuid": std_vmess["id"],
                "alterId": int(std_vmess["aid"]), "cipher": "auto",
                "tls": True if str(std_vmess["tls"]).lower() in ["tls", "1", "true"] else False,
                "skip-cert-verify": True, "network": std_vmess["net"]
            }
            if proxy["network"] == "ws":
                proxy["ws-opts"] = {"path": std_vmess["path"], "headers": {"Host": std_vmess["host"]}}
            elif proxy["network"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": std_vmess["path"]}

            new_json_str = json.dumps(std_vmess, separators=(',', ':'), ensure_ascii=False)
            new_b64 = base64.b64encode(new_json_str.encode('utf-8')).decode('utf-8')
            return label, proxy, f"vmess://{new_b64}"

        # --- 其他协议重构 ---
        elif "://" in link:
            base_url = link.split('#')[0].strip()
            old_remarks = urllib.parse.unquote(link.split('#')[1]) if '#' in link else ""
            
            u = urllib.parse.urlparse(link)
            label = get_final_label(u.hostname, old_remarks)
            
            # 兼容非 VMess 节点的 Clash 基本结构转换
            proto = link.split("://")[0].lower()
            proxy = {"name": new_name, "type": proto, "server": u.hostname, "port": u.port or 443}
            
            # 填充通用链接
            safe_name = urllib.parse.quote(new_name)
            return label, proxy, f"{base_url}#{safe_name}"

    except Exception:
        return None, None, None
    return None, None, None

def generate_clash_config(proxies):
    """生成能够直接导入客户端同步的完整 Clash 配置文件"""
    proxy_names = [p["name"] for p in proxies]
    
    config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": ["⚡ 自动测速", "🔮 直连"] + proxy_names
            },
            {
                "name": "⚡ 自动测速",
                "type": "url-test",
                "url": TEST_URL,
                "interval": 300,
                "tolerance": 50,
                "proxies": proxy_names
            },
            {
                "name": "🔮 直连",
                "type": "select",
                "proxies": ["DIRECT"]
            }
        ],
        "rules": [
            "GEOIP,CN,🔮 直连",
            "MATCH,🚀 节点选择"
        ]
    }
    
    with open('clash_config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)

def main():
    if not os.path.exists('nodes.txt'):
        print("❌ 未找到 nodes.txt")
        return

    load_cache()

    # 1. 读取与去重
    raw_links = []
    with open('nodes.txt', 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if "://" in line:
                raw_links.append(line)
    raw_links = list(dict.fromkeys(raw_links))
    print(f"📂 成功读取 {len(raw_links)} 个原始节点。正在解析归属地...")

    # 2. 第一阶段：归类
    grouped_nodes = defaultdict(list)
    for link in raw_links:
        label, _, _ = rebuild_node(link, "TEMP")
        if label:
            grouped_nodes[label].append(link)

    # 3. 第二阶段：排序并有序重构
    final_proxies_clash = []
    final_links_text = []
    
    for label in sorted(grouped_nodes.keys()):
        links_in_region = grouped_nodes[label]
        for idx, link in enumerate(links_in_region, start=1):
            new_name = f"{label} {idx:02d} {CHANNEL_MARK}"
            _, proxy, new_link = rebuild_node(link, new_name)
            if proxy and new_link:
                final_proxies_clash.append(proxy)
                final_links_text.append(new_link)

    # 4. 第三阶段：多格式输出保存
    if not final_links_text:
        print("⚠️ 没有成功转换任何节点。")
        save_cache()
        return

    # 输出 1: 纯文本
    with open('clean_nodes.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(final_links_text))

    # 输出 2: Base64 订阅文本
    all_links_str = "\n".join(final_links_text)
    b64_subscribe = base64.b64encode(all_links_str.encode('utf-8')).decode('utf-8')
    with open('subscribe.txt', 'w', encoding='utf-8') as f:
        f.write(b64_subscribe)

    # 输出 3: 完整的 Clash 配置文件
    generate_clash_config(final_proxies_clash)

    # 保存缓存
    save_cache()

    print(f"🟢 同步转换完成！")
    print(f"🔗 完整 Clash 配置已生成 -> clash_config.yaml (可直接用于同步)")
    print(f"📝 纯文本与Base64订阅已同步 -> clean_nodes.txt / subscribe.txt")

if __name__ == '__main__':
    main()
