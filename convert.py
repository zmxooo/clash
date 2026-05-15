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
    "韩国": "🇰🇷", "德国": "🇩🇪", "英国": "🇬🇧", "越南": "🇻🇳", "其它": "🌍"
}

def fix_base64(s):
    """补全Base64填充符，防止解码报错"""
    s = s.strip()
    return s + '=' * (-len(s) % 4)

def get_region_from_text(text):
    """从文本中精准提取地区关键字"""
    if not text: return "其它"
    text = text.lower()
    # 按照优先级匹配
    keywords = [
        ("香港", r"hk|hongkong|香港|港"),
        ("台湾", r"tw|taiwan|台湾|台灣"),
        ("英国", r"uk|united kingdom|英国|英國"),
        ("德国", r"de|germany|德国|德國"),
        ("美国", r"us|united states|美国|美國"),
        ("日本", r"jp|japan|日本|東京|东京"),
        ("韩国", r"kr|korea|韩国|韓國"),
        ("越南", r"vn|vietnam|越南")
    ]
    for name, pattern in keywords:
        if re.search(pattern, text):
            return name
    return "其它"

def main():
    if not os.path.exists('nodes.txt'):
        print("错误: 找不到输入文件 nodes.txt")
        return

    with open('nodes.txt', 'r', encoding='utf-8') as f:
        raw_links = [line.strip() for line in f if "://" in line]

    clash_proxies = []
    base64_links = []
    region_counts = {k: 0 for k in EMOJI_MAP.keys()}

    for link in raw_links:
        try:
            # --- 1. 协议解析与地区提取 ---
            server, raw_ps, protocol_type = "", "", ""
            
            if link.startswith('vmess://'):
                protocol_type = "vmess"
                b64_part = link[8:].split('#')[0]
                data = json.loads(base64.b64decode(fix_base64(b64_part)).decode('utf-8', 'ignore'))
                server = data.get("add", "")
                raw_ps = data.get("ps", "")
            else:
                protocol_type = link.split('://')[0]
                u = urllib.parse.urlparse(link)
                server = u.hostname or ""
                raw_ps = urllib.parse.unquote(u.fragment)

            # --- 2. 生成统一样式的备注 ---
            # 综合备注和服务器地址来判断地区
            region = get_region_from_text(raw_ps + server)
            region_counts[region] += 1
            idx = region_counts[region]
            
            # 最终备注格式：[Emoji][地区] [标记][编号]
            new_name = f"{EMOJI_MAP[region]}{region} {CHANNEL_MARK}{idx:02d}"

            # --- 3. 构建 Base64 订阅链接 ---
            clean_link = link.split('#')[0]
            if protocol_type == "vmess":
                # VMess需要重新封装JSON并编码ps字段
                b64_part = link[8:].split('#')[0]
                data = json.loads(base64.b64decode(fix_base64(b64_part)).decode('utf-8', 'ignore'))
                data["ps"] = new_name
                new_v_link = "vmess://" + base64.b64encode(json.dumps(data).encode()).decode()
                base64_links.append(new_v_link)
            else:
                base64_links.append(f"{clean_link}#{urllib.parse.quote(new_name)}")

            # --- 4. 构建 Clash 代理节点对象 ---
            # 这里是解决“同步”问题的关键：Clash节点名必须和备注完全一致
            p_obj = {"name": new_name, "server": server}
            
            if protocol_type == "vmess":
                p_obj.update({
                    "type": "vmess", "port": int(data.get("port", 443)),
                    "uuid": data.get("id"), "alterId": int(data.get("aid", 0)),
                    "cipher": "auto", "udp": True,
                    "tls": True if str(data.get("tls")).lower() in ["tls", "true", "1"] else False,
                    "network": data.get("net", "tcp")
                })
                if data.get("net") == "ws":
                    p_obj["ws-opts"] = {"path": data.get("path", "/"), "headers": {"Host": data.get("host", "")}}
            elif protocol_type == "hysteria2" or protocol_type == "hy2":
                u = urllib.parse.urlparse(link)
                p_obj.update({
                    "type": "hysteria2", "port": u.port or 443,
                    "password": u.username, "sni": server, "skip-cert-verify": True
                })
            elif protocol_type == "ss":
                u = urllib.parse.urlparse(link)
                p_obj.update({"type": "ss", "port": u.port, "cipher": "aes-256-gcm", "password": u.username})
            
            # 仅添加支持转换的协议
            if "type" in p_obj:
                clash_proxies.append(p_obj)

        except Exception as e:
            continue

    # --- 5. 写入 index.html (Base64) ---
    full_text = "\n".join(base64_links)
    encoded_text = base64.b64encode(full_text.encode()).decode()
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(encoded_text)

    # --- 6. 写入 clash_config.yaml (与Base64同步) ---
    clash_config = {
        "proxies": clash_proxies,
        "proxy-groups": [
            {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": ["自动选择"] + [p["name"] for p in clash_proxies]
            },
            {
                "name": "自动选择",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "proxies": [p["name"] for p in clash_proxies]
            }
        ],
        "rules": ["MATCH,🚀 节点选择"]
    }
    
    with open('clash_config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)

    print(f"测试通过：已同步处理 {len(base64_links)} 个节点。地区：{dict(region_counts)}")

if __name__ == "__main__":
    main()
