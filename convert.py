import base64, json, yaml, urllib.parse, os

# --- 核心配置：只负责添加编号和标记 ---
CHANNEL_MARK = "zmxooo"

def fix_base64_padding(s):
    """加固：处理 VMess 链接的 Base64 填充，防止解码崩溃"""
    s = s.strip().replace('-', '+').replace('_', '/')
    return s + '=' * (-len(s) % 4)

def main():
    if not os.path.exists('nodes.txt'):
        print("错误：未找到 nodes.txt")
        return

    with open('nodes.txt', 'r', encoding='utf-8') as f:
        # 只提取带备注（有 #）的链接
        links = [l.strip() for l in f if "://" in l and "#" in l]

    clash_proxies = []
    base64_links = []
    name_counters = {}

    for link in links:
        try:
            # 1. 提取协议和原始备注
            parts = link.split('#', 1)
            base_url = parts[0]
            raw_remark = parts[1]
            
            # 还原 URL 编码（解决 %E9 等编码问题）
            original_name = urllib.parse.unquote(raw_remark)
            
            # 2. 自动编号逻辑
            name_counters[original_name] = name_counters.get(original_name, 0) + 1
            idx = name_counters[original_name]
            # 生成最终名字：备注原文 + 编号 + 频道
            final_name = f"{original_name} {idx:02d} | @{CHANNEL_MARK}"

            # 3. 针对不同协议的重命名处理
            if base_url.startswith('vmess://'):
                # 穿透式重写：彻底抹除内部旧备注，强制同步
                v_content = base_url[8:]
                data = json.loads(base64.b64decode(fix_base64_padding(v_content)).decode('utf-8', 'ignore'))
                
                # 【核心修复】强制指定编码，禁止 JSON 转义，防止出现“恼国”乱码
                data["ps"] = final_name
                # ensure_ascii=False 是解决乱码的关键
                json_str = json.dumps(data, ensure_ascii=False)
                new_v_content = base64.b64encode(json_str.encode('utf-8')).decode()
                new_link = f"vmess://{new_v_content}"
                server = data.get("add", "")
                protocol = "vmess"
            else:
                # SS/Trojan/Hy2 直接拼接
                new_link = f"{base_url}#{urllib.parse.quote(final_name)}"
                server = urllib.parse.urlparse(base_url).hostname
                protocol = base_url.split('://')[0]

            # 4. 存入结果
            base64_links.append(new_link)
            clash_proxies.append({
                "name": final_name,
                "server": server,
                "type": protocol if protocol != "hy2" else "hysteria2",
                "port": 443 # 此处仅作示例，实际转换建议用专业后端
            })

        except Exception as e:
            continue

    # 5. 同时写入：确保 index 和 config 的名字绝对一致
    with open('index.html', 'w', encoding='utf-8') as f:
        # 整体再次 Base64 编码，生成订阅内容
        sub_content = "\n".join(base64_links)
        f.write(base64.b64encode(sub_content.encode('utf-8')).decode())
    
    with open('clash_config.yaml', 'w', encoding='utf-8') as f:
        # allow_unicode=True 保证 YAML 配置文件可读
        yaml.dump({"proxies": clash_proxies}, f, allow_unicode=True, sort_keys=False)

    print(f"测试通过！已根据备注重命名 {len(base64_links)} 个节点。")

if __name__ == "__main__":
    main()
