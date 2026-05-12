import base64
import json
import urllib.parse
import os
import re
import requests
import time
from collections import defaultdict

CHANNEL_MARK = "@zmxooo"
TEST_URL = "http://gstatic.com"

# 缓存 IP 识别结果
IP_CACHE = {}

# 图标映射
EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "美国": "🇺🇸", "英国": "🇬🇧", "韩国": "🇰🇷",
    "日本": "🇯🇵", "新加坡": "🇸🇬", "越南": "🇻🇳", "立陶宛": "🇱🇹", "科威特": "🇰🇼",
    "德国": "🇩🇪", "法国": "🇫🇷", "俄罗斯": "🇷🇺", "中国": "🇨🇳", "加拿大": "🇨🇦",
    "荷兰": "🇳🇱", "澳大利亚": "🇦🇺", "印度": "🇮🇳", "土耳其": "🇹🇷", "阿联酋": "🇦🇪",
}

def get_final_label(server, remarks):
    """识别国家并返回精简标签"""
    text = urllib.parse.unquote(str(remarks or "")).lower().strip()
    
    # 正则优先匹配
    meta = [
        ("香港", r"hk|hongkong|香港"), 
        ("台湾", r"tw|taiwan|台灣|台湾"), 
        ("美国", r"us|united states|美国|美國"), 
        ("英国", r"gb|uk|britain|英国|英國"),
        ("韩国", r"kr|korea|韩国|韓國"), 
        ("日本", r"jp|japan|日本"),
        ("新加坡", r"sg|singapore|新加坡"), 
        ("越南", r"vn|vietnam|越南"),
        ("德国", r"de|germany|德国"), 
        ("立陶宛", r"lt|lithuania|立陶宛"),
        ("法国", r"fr|france|法国"), 
        ("俄罗斯", r"ru|russia|俄罗斯"),
    ]
    for name, pattern in meta:
        if re.search(pattern, text):
            return f"{EMOJI_MAP.get(name, '🌍')} {name}"
    
    # IP 查询缓存
    if server in IP_CACHE:
        return IP_CACHE[server]

    # IP-API 查询
    try:
        time.sleep(0.3)
        resp = requests.get(f"http://ip-api.com/json/{server}?lang=zh-CN", timeout=6)
        data = resp.json()
        if data.get("status") == "success":
            country = data.get("country")
            icon = EMOJI_MAP.get(country, "🌍")
            label = f"{icon} {country}"
            IP_CACHE[server] = label
            return label
    except:
        pass
    
    return "🧿 其他地区"


def parse_link(link: str):
    """解析节点链接"""
    try:
        link = link.strip()
        if not link or link.startswith(('import', 'def', '#', 'git')):
            return None

        if link.startswith('vmess://'):
            b64_part = link[8:].split('#')[0]
            # 补全 Base64
            padding = len(b64_part) % 4
            if padding:
                b64_part += "=" * (4 - padding)
            
            data = json.loads(base64.b64decode(b64_part).decode('utf-8', errors='ignore'))
            
            proxy = {
                "type": "vmess",
                "name": "",  # 后面统一设置
                "server": data.get("add"),
                "port": int(data.get("port", 443)),
                "uuid": data.get("id"),
                "alterId": int(data.get("aid", 0)),
                "cipher": "auto",
                "tls": str(data.get("tls", "")).lower() in ["tls", "1", "true"],
                "skip-cert-verify": True,
                "network": data.get("net", "tcp"),
                "raw_json": data
            }
            
            if proxy["network"] == "ws":
                proxy["ws-opts"] = {
                    "path": data.get("path", "/"),
                    "headers": {"Host": data.get("host", data.get("add", ""))}
                }
            elif proxy["network"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": data.get("path", "")}
            
            return proxy

        elif link.startswith(('ss://', 'trojan://')):
            return {
                "type": "other",
                "link": link,
                "raw": link
            }

    except Exception:
        return None


def main():
    if not os.path.exists('nodes.txt'):
        print("❌ 未找到 nodes.txt 文件")
        return

    with open('nodes.txt', 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.read().splitlines()

    # 去重
    unique_links = []
    seen = set()
    for line in lines:
        line = line.strip()
        if line and line not in seen:
            unique_links.append(line)
            seen.add(line)

    region_map = defaultdict(list)
    clash_proxies = []
    rocket_links = []

    for link in unique_links:
        proxy = parse_link(link)
        if not proxy:
            continue

        label = get_final_label(
            proxy.get("server"), 
            link.split('#')[-1] if '#' in link else ""
        )
        
        idx = len(region_map[label]) + 1
        new_name = f"{label} {idx:02d} {CHANNEL_MARK}"

        # ==================== Shadowrocket ====================
        if proxy.get("type") == "vmess":
            d = proxy.pop("raw_json")
            d['ps'] = new_name
            b64 = base64.b64encode(json.dumps(d, separators=(',', ':')).encode()).decode()
            rocket_links.append(f"vmess://{b64}")
        else:
            # ss / trojan
            clean = link.split('#')[0]
            rocket_links.append(f"{clean}#{urllib.parse.quote(new_name)}")

        # ==================== Clash ====================
        if proxy.get("type") == "vmess":
            proxy["name"] = new_name
            clash_proxies.append(proxy)
        elif proxy.get("type") == "other":
            # 简单处理 ss/trojan（Clash Meta 支持）
            clash_proxies.append({
                "name": new_name,
                "type": "ss" if link.startswith('ss://') else "trojan",
                "server": proxy.get("server") or "unknown",
                "port": proxy.get("port", 443),
                # 其他字段建议用户手动补全或使用更完整的解析器
            })

        region_map[label].append(new_name)

    # ====================== 导出文件 ======================

    # 1. Shadowrocket 订阅 (Base64)
    if rocket_links:
        sub_content = "\n".join(rocket_links)
        sub_b64 = base64.b64encode(sub_content.encode('utf-8')).decode('utf-8')
        
        with open('rocket_sub.txt', 'w', encoding='utf-8') as f:
            f.write(sub_content)
        
        print(f"✅ 生成 Shadowrocket 订阅: {len(rocket_links)} 个节点")

    # 2. Clash 配置文件
    if clash_proxies:
        clash_config = {
            "proxies": clash_proxies,
            "proxy-groups": [
                {
                    "name": "♻️ 自动选择",
                    "type": "url-test",
                    "url": TEST_URL,
                    "interval": 300,
                    "tolerance": 50,
                    "proxies": [p["name"] for p in clash_proxies]
                },
                {
                    "name": "🚀 全局直连",
                    "type": "select",
                    "proxies": ["DIRECT", "♻️ 自动选择"]
                }
            ],
            "rules": [
                "MATCH,🚀 全局直连"
            ]
        }
        
        with open('clash_config.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
        
        print(f"✅ 生成 Clash 配置: {len(clash_proxies)} 个节点")

    # 3. HTML 一键订阅页面
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>节点订阅 - {CHANNEL_MARK}</title>
    <style>
        body {{ font-family: system-ui; text-align: center; padding: 50px; background: #0f0f0f; color: #0f0; }}
        h1 {{ color: #0f0; }}
        .btn {{ 
            display: inline-block; margin: 15px; padding: 15px 30px; 
            background: #111; color: #0f0; text-decoration: none; 
            border: 2px solid #0f0; border-radius: 8px; font-size: 18px;
        }}
        .btn:hover {{ background: #0f0; color: #000; }}
    </style>
</head>
<body>
    <h1>节点订阅</h1>
    <p>共 {len(rocket_links)} 个节点 | 更新时间: {time.strftime("%Y-%m-%d %H:%M:%S")}</p>
    <a href="data:text/plain;base64,{sub_b64}" class="btn" download="sub.txt">📥 下载订阅文件</a><br>
    <a href="https://sub.xn--mesv.xn--6qq986b3xl/sub?target=clash&url=data:text/plain;base64,{sub_b64}" class="btn" target="_blank">🚀 Clash 一键导入</a>
</body>
</html>"""

    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(html)

    print("✅ 生成 index.html 订阅页面")
    print(f"总节点数: {len(rocket_links)}")


if __name__ == "__main__":
    main()
