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
IP_CACHE = {}

# 常用图标映射
EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "美国": "🇺🇸", "英国": "🇬🇧", "韩国": "🇰🇷", 
    "日本": "🇯🇵", "新加坡": "🇸🇬", "越南": "🇻🇳", "立陶宛": "🇱🇹", "科威特": "🇰🇼",
    "德国": "🇩🇪", "法国": "🇫🇷", "俄罗斯": "🇷🇺", "中国": "🇨🇳", "加拿大": "🇨🇦"
}

def get_final_label(server, remarks):
    """
    国家识别逻辑：优先正则匹配备注，其次查询 IP 库
    """
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
        # 限制请求频率，防止被 API 封锁
        time.sleep(0.1) 
        response = requests.get(f"http://ip-api.com{server}?lang=zh-CN", timeout=5).json()
        if response.get("status") == "success":
            country = response.get("country")
            label = f"{EMOJI_MAP.get(country, '🌍')} {country}"
            IP_CACHE[server] = label
            return label
    except:
        pass
    return "🧿 其它地区"

def fix_base64(s):
    """
    修正 Base64 格式：去除空白符并自动补齐等号
    """
    if not s: return ""
    s = "".join(s.split()) # 移除换行、空格
    return s + '=' * (-len(s) % 4)

def rebuild_node(link, new_name):
    """
    重构节点：剥离一切原始信息，强制使用标准格式 and 新命名
    """
    try:
        # --- VMess 协议重构 ---
        if link.startswith('vmess://'):
            b64_part = link[8:].split('#')[0]
            decoded_bytes = base64.b64decode(fix_base64(b64_part))
            d = json.loads(decoded_bytes.decode('utf-8', 'ignore'))
            
            # 1. 识别国家（用于返回 label）
            label = get_final_label(d.get("add"), d.get("ps", ""))
            
            # 2. 构建纯净版 VMess 字典，强制 v=2 和 ps=new_name
            std_vmess = {
                "v": "2",
                "ps": new_name,
                "add": str(d.get("add", "")).strip(),
                "port": str(d.get("port", "443")),
                "id": str(d.get("id", "")).strip(),
                "aid": str(d.get("aid", "0")),
                "scy": d.get("scy", "auto"),
                "net": d.get("net", "tcp"),
                "type": d.get("type", "none"),
                "host": d.get("host", ""),
                "path": d.get("path", ""),
                "tls": d.get("tls", ""),
                "sni": d.get("sni", ""),
                "alpn": d.get("alpn", "")
            }
            
            # 3. 生成 Clash 节点对象
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
            # 处理传输层配置
            if proxy["network"] == "ws":
                proxy["ws-opts"] = {"path": std_vmess["path"], "headers": {"Host": std_vmess["host"]}}
            elif proxy["network"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": std_vmess["path"]}

            # 4. 生成通用链接 (Base64)
            new_json_str = json.dumps(std_vmess, separators=(',', ':'), ensure_ascii=False)
            new_b64 = base64.b64encode(new_json_str.encode('utf-8')).decode('utf-8')
            return label, proxy, f"vmess://{new_b64}"

        # --- 其他协议 (Hysteria2 / SS / Trojan / VLESS) 重构 ---
        elif "://" in link:
            # 1. 彻底切断原始备注 (# 之后的内容)
            base_url = link.split('#')[0].strip()
            old_remarks = urllib.parse.unquote(link.split('#')[1]) if '#' in link else ""
            
            # 2. 识别国家
            u = urllib.parse.urlparse(link)
            label = get_final_label(u.hostname, old_remarks)
            
            # 3. 构建 Clash 对象 (简易版，直接存 link)
            proxy = {"name": new_name, "type": "other", "link": link}
            
            # 4. 生成通用链接：地址 + URL 编码后的新名字
            safe_name = urllib.parse.quote(new_name)
            return label, proxy, f"{base_url}#{safe_name}"

    except Exception:
        return None, None, None

def main():
    if not os.path.exists('nodes.txt'):
        print("❌ 未找到 nodes.txt")
        return

    # 读取并初步清洗链接
    with open('nodes.txt', 'r', encoding='utf-8') as f:
        # 只保留包含协议头的行，并去重
        links = list(set([line.strip() for line in f if "://" in line]))

    clash_proxies = []
    proxy_names = []
    country_counters = defaultdict(int)

    for link in links:
        # 预解析获取真实的节点国家标签
        temp_label, _, _ = rebuild_node(link, "temp")
        if not temp_label:
            continue
            
        # 提取国家名称进行计数器累加
        country_name = temp_label.split()[-1] if " " in temp_label else temp_label
        country_counters[country_name] += 1
        
        # 严格使用你预设的命名拼接规则
        new_name = f"{temp_label} {country_counters[country_name]:02d} {CHANNEL_MARK}"
        
        # 正式重构并提取 Clash 节点对象
        _, proxy, _ = rebuild_node(link, new_name)
        if proxy:
            clash_proxies.append(proxy)
            proxy_names.append(new_name)

    yaml_path = 'config.yaml'
    config_data = {}
    
    # 如果 config.yaml 存在则读取，不存在则初始化结构
    if os.path.exists(yaml_path):
        with open(yaml_path, 'r', encoding='utf-8') as f:
            try:
                config_data = yaml.safe_load(f) or {}
            except:
                pass

    # 将生成的代理数据注入配置字典
    config_data["proxies"] = clash_proxies
    if "proxy-groups" not in config_data:
        config_data["proxy-groups"] = [{"name": "🚀 节点选择", "type": "select", "proxies": []}]
    
    for group in config_data["proxy-groups"]:
        if group.get("name") == "🚀 节点选择":
            group["proxies"] = proxy_names

    # 物理覆盖写入 config.yaml 文件
    with open(yaml_path, 'w', encoding='utf-8') as f:
        yaml.dump(config_data, f, allow_unicode=True, sort_keys=False)
    
    print(f"✅ 成功将 {len(clash_proxies)} 个节点自动写入到 config.yaml")

if __name__ == "__main__":
    main()
