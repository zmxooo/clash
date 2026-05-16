import os
import re
import sys
import json
import time
import yaml
import subprocess
from concurrent.futures import ThreadPoolExecutor

MAX_WORKERS = 40
TIMEOUT = 4

def download_mihomo_core():
    """直接读取系统 `.yml` 提前注入并完全授权好的纯正二进制内核"""
    core_path = "./mihomo"
    if os.path.exists(core_path):
        # 再次执行最终安全提权防线
        os.chmod(core_path, 0o755)
        print("🎉 成功挂载由系统级工作流注入的高可用原生内核，开始构建测速隧道...")
        return core_path
        
    print("致命缺陷：找不到本地核心，请检查 .yml 文件的强制注入步骤。")
    sys.exit(1)

def run_test_on_single_node(node_index, node_name, local_socks_port):
    """探针：并发捕获 100% 精准的底层物理出口位置"""
    api_url = "http://ip-api.com"
    cmd = ["curl", "-s", "--socks5-hostname", f"127.0.0.1:{local_socks_port}", "--max-time", str(TIMEOUT), api_url]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0 and result.stdout:
            data = json.loads(result.stdout)
            if data.get("status") == "success":
                country = data.get("country", "未知")
                country_code = data.get("countryCode", "").upper()
                
                emoji_map = {
                    "HK": "🇭🇰", "TW": "🇹🇼", "US": "🇺🇸", "GB": "🇬🇧", "KR": "🇰🇷", 
                    "JP": "🇯🇵", "SG": "🇸🇬", "VN": "🇻🇳", "DE": "🇩🇪", "FR": "🇫🇷", 
                    "RU": "🇷🇺", "CN": "🇨🇳", "CA": "🇨🇦", "IR": "🇮🇷", "NL": "🇳🇱", 
                    "TR": "🇹🇷", "IN": "🇮🇳", "MY": "🇲🇾", "PH": "🇵🇭", "TH": "🇹🇭"
                }
                emoji = emoji_map.get(country_code, "🌍")
                print(f"✅ 节点 [{node_name}] 测试成功 -> 真实出口: {emoji} {country}")
                return node_index, f"{emoji} {country}"
    except:
        pass
    print(f"❌ 节点 [{node_name}] 超时或不可用")
    return node_index, None

def start_speedtest_pipeline(valid_proxies):
    if not valid_proxies:
        print("没有可用的节点进行测速")
        return valid_proxies

    core_bin = download_mihomo_core()
    temp_proxies = []
    temp_groups = []
    base_port = 20000
    
    for idx, proxy in enumerate(valid_proxies):
        p_copy = proxy.copy()
        p_copy["name"] = f"test_node_{idx}"
        temp_proxies.append(p_copy)
        local_port = base_port + idx
        temp_groups.append({
            "name": f"group_{idx}",
            "type": "select",
            "proxies": [f"test_node_{idx}"],
            "port": local_port
        })
        
    temp_config = {
        "mode": "rule",
        "log-level": "silent",
        "proxies": temp_proxies,
        "proxy-groups": temp_groups,
        "rules": ["MATCH,DIRECT"]
    }
    
    with open("speedtest_clash.yaml", "w", encoding="utf-8") as f:
        yaml.dump(temp_config, f, allow_unicode=True)
        
    print("正在启动后台测速隧道核心...")
    proc = subprocess.Popen([core_bin, "-f", "speedtest_clash.yaml"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    
    print(f"开始并行测速校准（最大线程数: {MAX_WORKERS}）...")
    results = {}
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for idx, p in enumerate(valid_proxies):
            task = executor.submit(run_test_on_single_node, idx, p.get("name", f"Node_{idx}"), base_port + idx)
            futures.append(task)
            
        for future in futures:
            idx, label = future.result()
            if label:
                results[idx] = label
                
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        
    if os.path.exists("speedtest_clash.yaml"): 
        os.remove("speedtest_clash.yaml")
    
    final_proxies = []
    for idx, p in enumerate(valid_proxies):
        if idx in results:
            real_label = results[idx]
            clean_num = re.sub(r'[^0-9]', '', p.get("name", ""))
            p["name"] = f"{real_label} {clean_num if clean_num else idx} @zmxooo"
            
            if "label" in p: del p["label"]
            if "raw_json" in p: del p["raw_json"]
            final_proxies.append(p)
            
    return final_proxies
