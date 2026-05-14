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
IP_CACHE = {}

# 1. 补全全球主要国家图标
EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "日本": "🇯🇵", "韩国": "🇰🇷", "新加坡": "🇸🇬", 
    "中国": "🇨🇳", "越南": "🇻🇳", "泰国": "🇹🇭", "菲律宾": "🇵🇭", "马来西亚": "🇲🇾", 
    "印度": "🇮🇳", "土耳其": "🇹🇷", "阿联酋": "🇦🇪", "美国": "🇺🇸", "加拿大": "🇨🇦", 
    "英国": "🇬🇧", "德国": "🇩🇪", "法国": "🇫🇷", "俄罗斯": "🇷🇺", "荷兰": "🇳🇱", 
    "澳大利亚": "🇦🇺", "巴西": "🇧🇷", "阿根廷": "🇦🇷", "新西兰": "🇳🇿", "意大利": "🇮🇹"
}

def get_final_label(server, remarks):
    """识别地区逻辑"""
    try:
        text = urllib.parse.unquote(str(remarks)).lower().strip()
        # 补全正则识别库
        meta = [
            ("香港", r"hk|hong|香港"), ("台湾", r"tw|taiwan|台湾|台灣"), 
            ("美国", r"us|united states|america|美国|美國"), ("英国", r"gb|uk|united kingdom|英国|英國"), 
            ("韩国", r"kr|korea|韩国|韓國"), ("日本", r"jp|japan|日本"),
            ("新加坡", r"sg|singapore|新加坡"), ("越南", r"vn|vietnam|越南"), 
            ("德国", r"de|germany|德国"), ("法国", r"fr|france|法国"),
            ("俄罗斯", r"ru|russia|俄罗斯"), ("泰国", r"th|thailand|泰国"),
            ("加拿大", r"ca|canada|加拿大"), ("澳大利亚", r"au|australia|澳洲"),
            ("荷兰", r"nl|netherlands|荷兰"), ("菲律宾", r"ph|philippines|菲律宾")
        ]
        for name, pattern in meta:
            if re.search(pattern, text): 
                return f"{EMOJI_MAP.get(name, '🌍')} {name}"
        
        if server in IP_CACHE: return IP_CACHE[server]
        
        # IP API 查询
        time.sleep(0.1) 
        resp = requests.get(f"http://ip-api.com/json/{server}?lang=zh-CN", timeout=5).json()
        if resp.get("status") == "success":
            country = resp.get("country")
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
    重构节点逻辑。
    返回 (label, proxy_dict, final_link)
    """
    try:
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

            new_json_str = json.dumps(std_vmess, separators=(',', ':'), ensure_ascii=False)
            new_b64 = base64.b64encode(new_json_str.encode('utf-8')).decode('utf-8')
            return label, proxy, f"vmess://{new_b64}"

        elif "://" in link:
            # 处理 SS/VLESS/Trojan 等
            base_url = link.split('#')[0].strip()
            old_remarks = urllib.parse.unquote(link.split('#')[1]) if '#' in link else ""
            u = urllib.parse.urlparse(link)
            label = get_final_label(u.hostname, old_remarks)
            # 对于非 VMess 节点，暂不转换成 Clash 配置（保持你原始脚本的逻辑）
            return label, None, f"{base_url}#{urllib.parse.quote(new_name)}"
    except:
        pass
    return "🧿 其它地区", None, None

def main():
    if not os.path.exists('nodes.txt'):
        print("nodes.txt 不存在")
        return

    # 1. 强力读取链接，过滤空行
    with open('nodes.txt', 'r', encoding='utf-8', errors='ignore') as f:
        raw_links = list(dict.fromkeys([line.strip() for line in f if "://" in line]))

    # 2. 预处理识别地区（为了排序）
    # 这一步非常关键，增加了安全性，防止 unpack 报错导致脚本崩溃
    parsed_items = []
    for link in raw_links:
        res = rebuild_node(link, "TEMP")
        if res and len(res) == 3:
            label = res[0]
            parsed_items.append({"label": label, "link": link})
    
    # 按地区排序
    parsed_items.sort(key=lambda x: x["label"])

    final_links = []
    clash_proxies = []
    counters = defaultdict(int)

    # 3. 正式重命名并构建列表
    for item in parsed_items:
        label = item["label"]
        counters[label] += 1
        new_name = f"{label} {counters[label]:02d} | {CHANNEL_MARK}"
        
        _, proxy, flink = rebuild_node(item["link"], new_name)
        if flink:
            final_links.append(flink)
            if proxy: # 如果解析成功且不为 None，就存入 Clash
                clash_proxies.append(proxy)

    # 4. 强制写入文件
    # 先处理 HTML 订阅内容
    content_b64 = base64.b64encode("\n".join(final_links).encode('utf-8')).decode('utf-8')
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(content_b64)

    # 后处理 YAML 配置
    with open('config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump({"proxies": clash_proxies}, f, allow_unicode=True, sort_keys=False)
    
    print(f"成功更新！共处理 {len(final_links)} 个节点。")

if __name__ == "__main__":
    main()
