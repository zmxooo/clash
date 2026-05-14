import base64
import json
import yaml
import urllib.parse
import os
import re
import requests
import time
from collections import defaultdict

CHANNEL_MARK = "@zmxooo"
IP_CACHE = {}

# 1. 核心识别：IP 真实位置查询 + 备注匹配
def get_final_label(server, remarks):
    text = urllib.parse.unquote(str(remarks)).lower().strip()
    meta = [
        ("🇭🇰 香港", r"hk|香港|hongkong|🇭🇰"), ("🇹🇼 台湾", r"tw|台湾|台灣|taiwan|🇹🇼"),
        ("🇺🇸 美国", r"us|美国|美國|america|usa|🇺🇸"), ("🇰🇷 韩国", r"kr|韩国|韓國|korea|🇰🇷"),
        ("🇯🇵 日本", r"jp|日本|japan|🇯🇵"), ("🇸🇬 新加坡", r"sg|新加坡|singapore|🇸🇬"),
        ("🇩🇪 德国", r"de|德国|德國|germany|ger|🇩🇪"), ("🇬🇧 英国", r"gb|uk|英国|英國|united kingdom|🇬🇧"),
        ("🇻🇳 越南", r"vn|越南|vietnam|🇻🇳"), ("🇱🇹 立陶宛", r"lt|立陶宛|lithuania"),
        ("🇷🇺 俄罗斯", r"ru|俄罗斯|俄羅斯|russia|🇷🇺"),
    ]
    for label, pattern in meta:
        if re.search(pattern, text): return label
    
    if server and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', server):
        if server in IP_CACHE:
            return IP_CACHE[server]
        try:
            time.sleep(0.1)
            r = requests.get(f"ip-api.com{server}?lang=zh-CN", timeout=3).json()
            if r.get("status") == "success":
                c = r.get("country")
                country_map = {"中国": "🇨🇳 中国", "香港": "🇭🇰 香港", "台湾": "🇹🇼 台湾", "美国": "🇺🇸 美国", "日本": "🇯🇵 日本", "韩国": "🇰🇷 韩国", "新加坡": "🇸🇬 新加坡", "德国": "🇩🇪 德国", "英国": "🇬🇧 英国", "越南": "🇻🇳 越南", "立陶宛": "🇱🇹 立陶宛"}
                label = country_map.get(c, f"🌍 {c}")
                IP_CACHE[server] = label
                return label
        except: pass
    return "🌍 其他"

# 2. 完美适配的全量协议解析器
def parse_link(link):
    try:
        link = link.strip()
        if not link: return None
        if link.startswith('vmess://vmess://'): link = link[8:]
        
        # 允许 urlparse 自行处理包含 # fragment 在内的完整标准 URL
        u = urllib.parse.urlparse(link)
        
        # --- VMess ---
        if link.startswith('vmess://'):
            b64 = link[8:].split('#')[0]
            b64 += '=' * (-len(b64) % 4)
            d = json.loads(base64.b64decode(b64).decode('utf-8'))
            server_ip = d.get("add")
            return {
                "label": get_final_label(server_ip, d.get("ps")), 
                "type": "vmess", 
                "server": server_ip, 
                "port": int(d.get("port")), 
                "uuid": d.get("id"), 
                "alterId": 0, 
                "cipher": "auto", 
                "tls": d.get("tls") in ["tls", True, 1], 
                "skip-cert-verify": True,
                "network": d.get("net", "tcp"),
                "ws-opts": {"path": d.get("path", "/")} if d.get("net") == "ws" else {}
            }

        # --- VLESS / Trojan / TUIC ---
        elif any(link.startswith(p) for p in ['vless://', 'trojan://', 'tuic://']):
            q = urllib.parse.parse_qs(u.query)
            p_type = link.split(':')[0]
            sni = q.get("sni", [""]) or q.get("host", [""]) or [u.hostname]
            
            p = {
                "label": get_final_label(u.hostname, u.fragment), 
                "type": p_type, 
                "server": u.hostname, 
                "port": int(u.port) if u.port else 443, 
                "tls": True, 
                "sni": str(sni[0]) if sni else u.hostname, 
                "skip-cert-verify": True, 
                "udp": True
            }
            if p_type == "vless": 
                p.update({"uuid": u.username, "cipher": "auto", "network": q.get("type", ["tcp"])[0]})
                if q.get("security", [""])[0] == "reality":
                    p["reality-opts"] = {"public-key": q.get("pbk", [""])[0]}
            elif p_type == "tuic": 
                p.update({"uuid": u.username, "password": u.password, "alpn": q.get("alpn", ["h3"])})
            else: 
                p["password"] = u.username
            return p

        # --- Shadowsocks (SS) ---
        elif link.startswith('ss://'):
            if "@" in u.netloc:
                userinfo, server = u.netloc.split("@")
                userinfo += '=' * (-len(userinfo) % 4)
                method, password = base64.b64decode(userinfo).decode().split(":", 1)
                host, port = server.split(":")
            else:
                decoded = base64.b64decode(u.netloc + '=' * (-len(u.netloc) % 4)).decode().split(":", 1)
                method = decoded[0]
                password, host_port = decoded[1].rsplit("@", 1)
                host, port = host_port.split(":")
            return {"label": get_final_label(host, u.fragment), "type": "ss", "server": host, "port": int(port), "cipher": method, "password": password, "udp": True}

        # --- Hysteria 1 & 2 (终极无损解析) ---
        elif any(link.startswith(p) for p in ['hysteria://', 'hysteria2://', 'hy2://']):
            p_type = "hysteria2" if "2" in link or "hy2" in link else "hysteria"
            q = urllib.parse.parse_qs(u.query)
            sni_val = q.get("sni", [""])[0] if q.get("sni") else u.hostname
            
            # 使用完全没问题的原生属性直接提取
            return {
                "label": get_final_label(u.hostname, u.fragment), 
                "type": p_type, 
                "server": u.hostname, 
                "port": int(u.port) if u.port else 443, 
                "password": u.username, 
                "auth": u.username, 
                "sni": sni_val, 
                "skip-cert-verify": q.get("insecure", [""])[0] != "0",
                "alpn": q.get("alpn", ["h3"])
            }

    except Exception as e: 
        return None
    return None

# 3. 主控重写与输出存储
def main():
    if not os.path.exists('nodes.txt'):
        print("❌ 未找到 nodes.txt 文件")
        return

    with open('nodes.txt', 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.read().splitlines()
    
    seen = set()
    unique_links = []
    for line in lines:
        line = line.strip()
        if not line: continue
        # 去重对比：去掉原备注信息，保证唯一性
        core_link = line.split('#')[0]
        if core_link not in seen:
            seen.add(core_link)
            unique_links.append(line)

    clash_proxies = []
    rocket_links = []
    name_count = {}
    
    print(f"🔄 正在融合清洗 {len(unique_links)} 个去重后的节点...")
    
    for l in unique_links:
        p = parse_link(l)
        if p:
            # 1. 计算重命名系统
            base_label = p.pop('label')
            name_count[base_label] = name_count.get(base_label, 0) + 1
            new_name = f"{base_label} {name_count[base_label]:02d} {CHANNEL_MARK}"
            
            # 2. 重写小火箭订阅格式
            # 还原干净的 URL 基础部分（丢弃旧 fragment），追加标准编码的新备注
            u_obj = urllib.parse.urlparse(l)
            clean_url_without_hash = l.split('#')[0]
            rocket_links.append(f"{clean_url_without_hash}#{urllib.parse.quote(new_name)}")
            
            # 3. 压入 Clash 字典
            p['name'] = new_name
            # 字段微调适配 Clash 的标准命名
            if p['type'] == "hysteria":
                p['auth-str'] = p.pop('password', '')
            clash_proxies.append(p)

    # 保存重写文件
    try:
        with open('rocket_output.txt', 'w', encoding='utf-8') as f:
            f.write("\n".join(rocket_links))
        
        with open('clash_output.yaml', 'w', encoding='utf-8') as f:
            yaml.dump({"proxies": clash_proxies}, f, allow_unicode=True, sort_keys=False)
            
        print(f"✅ 转换完成！成功输出小火箭节点 {len(rocket_links)} 个，Clash 节点 {len(clash_proxies)} 个。")
    except Exception as e:
        print(f"❌ 写入文件失败: {e}")

if __name__ == "__main__":
    main()
