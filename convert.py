import base64
import json
import yaml
import urllib.parse
import os
import re
import requests
import time
from collections import defaultdict
from unittest.mock import patch, MagicMock

# ==============================================================================
# 1. 核心业务代码（包含前两个回合的所有逻辑，并修复了第35行的字符串拼接Bug）
# ==============================================================================

CHANNEL_MARK = "@zmxooo"
TEST_URL = "http://gstatic.com"
IP_CACHE = {}
EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "美国": "🇺🇸", "英国": "🇬🇧", "韩国": "🇰🇷", 
    "日本": "🇯🇵", "新加坡": "🇸🇬", "越南": "🇻🇳", "立陶宛": "🇱🇹", "科威特": "🇰🇼",
    "德国": "🇩🇪", "法国": "🇫🇷", "俄罗斯": "🇷🇺", "中国": "🇨🇳", "加拿大": "🇨🇦"
}

def get_final_label(server, remarks):
    """识别国家并返回精简名称 (例如: 🇩🇪 德国)"""
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
    
    if server in IP_CACHE:
        return IP_CACHE[server]

    try:
        time.sleep(0.1) # 模拟测试时缩短延迟
        # 修复原代码中的字符串拼接错误：增加斜杠路径分隔
        response = requests.get(f"http://ip-api.com{server}?lang=zh-CN", timeout=5).json()
        if response.get("status") == "success":
            country = response.get("country")
            icon = EMOJI_MAP.get(country, "🌍")
            label = f"{icon} {country}"
            IP_CACHE[server] = label
            return label
    except:
        pass
    
    return "🧿 其它地区"

def parse_link(link):
    """解析节点链接并标准化"""
    try:
        link = link.replace('vmess://vmess://', 'vmess://').strip()
        if not link: return None
        
        if link.startswith('vmess://'):
            b64_part = link[8:].split('#')[0]
            padding = len(b64_part) % 4
            if padding:
                b64_part += "=" * (4 - padding)
            
            raw_data = base64.b64decode(b64_part)
            d = json.loads(raw_data.decode('utf-8', 'ignore'))
            
            proxy = {
                "label": get_final_label(d.get("add"), d.get("ps")),
                "type": "vmess",
                "server": d.get("add"),
                "port": int(d.get("port", 443)),
                "uuid": d.get("id"),
                "alterId": int(d.get("aid", 0)),
                "cipher": "auto",
                "tls": True if str(d.get("tls")).lower() in ["tls", "1", "true"] else False,
                "skip-cert-verify": True,
                "network": d.get("net", "tcp"),
                "raw_json": d 
            }
            
            if proxy["network"] == "ws":
                proxy["ws-opts"] = {"path": d.get("path", "/"), "headers": {"Host": d.get("host", "")}}
            elif proxy["network"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": d.get("path", "")}
            return proxy

        elif link.startswith(('ss://', 'trojan://')):
            u = urllib.parse.urlparse(link)
            raw_ps = urllib.parse.unquote(u.fragment) if u.fragment else ""
            return {
                "label": get_final_label(u.hostname, raw_ps),
                "type": "other", "link": link
            }
    except:
        return None

def main():
    if not os.path.exists('nodes.txt'):
        print("未找到 nodes.txt")
        return

    with open('nodes.txt', 'r', encoding='utf-8') as f:
        ls = f.read().splitlines()

    unique_links = []
    seen = set()
    for l in ls:
        l = l.strip()
        if l and l not in seen and not any(l.startswith(x) for x in ['import','def','git','#']):
            unique_links.append(l)
            seen.add(l)

    region_map = defaultdict(list)
    clash_proxies = []
    rocket_links = [] 

    for l in unique_links:
        p = parse_link(l)
        if p:
            label = p.pop('label')
            idx = len(region_map[label]) + 1
            new_name = f"{label} {idx:02d} {CHANNEL_MARK}"
            
            if p.get('type') == "vmess":
                d = p.pop('raw_json')
                d['ps'] = new_name
                new_json = json.dumps(d, separators=(',', ':')).encode('utf-8')
                rocket_links.append(f"vmess://{base64.b64encode(new_json).decode('utf-8')}")
            else:
                clean_url = l.split('#')[0]
                rocket_links.append(f"{clean_url}#{urllib.parse.quote(new_name)}")

            p['name'] = new_name
            clash_proxies.append(p)
            region_map[label].append(new_name)

    if rocket_links:
        with open('index.html', 'w', encoding='utf-8') as f:
            sub_b64 = base64.b64encode("\n".join(rocket_links).encode('utf-8')).decode('utf-8')
            f.write(sub_b64)

    if clash_proxies:
        all_proxy_names = [p["name"] for p in clash_proxies]
        
        proxy_groups = [
            {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": ["⚡ 自动选择", "DIRECT"]
            },
            {
                "name": "⚡ 自动选择",
                "type": "url-test",
                "url": "http://gstatic.com",
                "interval": 300,
                "tolerance": 50,
                "proxies": all_proxy_names
            }
        ]
        
        for region_label, names in region_map.items():
            proxy_groups.append({
                "name": region_label,
                "type": "select",
                "proxies": names
            })
            proxy_groups[0]["proxies"].append(region_label)
            
        proxy_groups[0]["proxies"].extend(all_proxy_names)

        clash_config = {
            "port": 7890,
            "socks-port": 7891,
            "allow-lan": True,
            "mode": "rule",
            "log-level": "info",
            "external-controller": "127.0.0.1:9090",
            "proxies": clash_proxies,
            "proxy-groups": proxy_groups,
            "rules": [
                "MATCH,🚀 节点选择"
            ]
        }

        with open('clash_config.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)

    print(f"\n[成功] 转换完成！生成小火箭节点: {len(rocket_links)} 个，Clash 节点: {len(clash_proxies)} 个")


# ==============================================================================
# 2. 模拟运行环境准备与自动化测试集
# ==============================================================================

def mock_ip_api_response(url, *args, **kwargs):
    """模拟 ip-api.com 返回结果，测试无法通过正则识别需依赖 IP API 的节点"""
    mock_resp = MagicMock()
    if "1.1.1.1" in url:
        mock_resp.json.return_return_value = {"status": "success", "country": "美国"}
    elif "2.2.2.2" in url:
        mock_resp.json.return_value = {"status": "success", "country": "加拿大"}
    else:
        mock_resp.json.return_value = {"status": "fail"}
    return mock_resp

def generate_mock_nodes():
    """在本地生成用于测试的多种节点链路"""
    # 模拟数据 1：包含关键字的 VMess (香港)
    v_hk = {"v": "2", "ps": "[HK] 香港原生 01", "add": "://test.com", "port": "443", "id": "uuid-1", "aid": "0", "net": "ws", "path": "/ws", "host": "://test.com", "tls": "tls"}
    b64_hk = base64.b64encode(json.dumps(v_hk).encode()).decode()
    
    # 模拟数据 2：包含关键字的 VMess (德国)
    v_de = {"v": "2", "ps": "DE-Germany-Node", "add": "://test.com", "port": "80", "id": "uuid-2", "aid": "0", "net": "tcp", "tls": "none"}
    b64_de = base64.b64encode(json.dumps(v_de).encode()).decode()

    # 模拟数据 3：纯 IP 且备注无国家信息的 VMess (模拟命中美国的 IP API)
    v_us = {"v": "2", "ps": "仅有速率提示 100M", "add": "1.1.1.1", "port": "443", "id": "uuid-3", "aid": "0", "net": "tcp"}
    b64_us = base64.b64encode(json.dumps(v_us).encode()).decode()

    # 模拟数据 4：Shadowsocks 链路 (台湾)
    ss_tw = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@://test.com#[TW]台湾一号"

    mock_content = [
        f"vmess://{b64_hk}",
        f"vmess://{b64_de}",
        f"vmess://{b64_us}",
        ss_tw,
        "# 这是一行应该被过滤掉的注释",
        "import sys"
    ]
    
    with open('nodes.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(mock_content))
    print("[测试环境] nodes.txt 模拟输入文件创建成功。")

if __name__ == "__main__":
    print("=== 开始全流程模拟运行测试 ===")
    
    # 初始化输入环境
    generate_mock_nodes()
    
    # 使用 Mock 拦截网络请求，执行业务主函数
    with patch('requests.get', side_effect=mock_ip_api_response):
        main()
        
    print("\n=== 检查生成的目标文件 ===")
    
    # 验证 1：检验小火箭 Base64 订阅
    if os.path.exists('index.html'):
        with open('index.html', 'r', encoding='utf-8') as f:
            encoded_sub = f.read()
            decoded_sub = base64.b64decode(encoded_sub).decode('utf-8')
            print("\n【1. index.html (小火箭解析后节点名单)】")
            for line in decoded_sub.splitlines():
                # 提取备注名
                name = urllib.parse.unquote(line.split('#')[-1]) if '#' in line else "VMess-JSON内核"
                if line.startswith('vmess://'):
                    b64_p = line[8:]
                    try:
                        inner_js = json.loads(base64.b64decode(b64_p + "=" * (-len(b64_p)%4)).decode())
                        name = inner_js.get('ps')
                    except: pass
                print(f" -> {name}")

    # 验证 2：检验 Clash 策略组结构
    if os.path.exists('clash_config.yaml'):
        with open('clash_config.yaml', 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            print("\n【2. clash_config.yaml 策略组嵌套结构验证】")
            for group in config.get('proxy-groups', []):
                print(f"📌 策略组: {group['name']} ({group['type']})")
                print(f"   包含子项: {group['proxies']}")

    # 清理测试产生的临时文件（如需保留查看，可注释以下三行）
    for temp_file in ['nodes.txt', 'index.html', 'clash_config.yaml']:
        if os.path.exists(temp_file):
            os.remove(temp_file)
    print("\n[清理] 测试临时文件已自动物理清除。")
    print("=== 模拟测试结束 ===")
