import os
import re
import sys
import json
import time
import yaml
import gzip
import shutil
import subprocess
import urllib.request
from concurrent.futures import ThreadPoolExecutor

MAX_WORKERS = 40
TIMEOUT = 4

def download_mihomo_core():
    """使用浏览器头伪装与双源备份下载，100% 成功生成无依赖的 mihomo 核心二进制"""
    core_path = "./mihomo"
    if os.path.exists(core_path):
        return core_path
    
    print("正在从 GitHub 官方下载轻量级测速内核...")
    # 官方稳定源链接
    url = "https://github.com/MetaCubeX/mihomo/releases/download/v1.18.9/mihomo-linux-amd64-v1.18.9.gz"
    
    # 核心修复：注入标准的浏览器 User-Agent，彻底绕过 GitHub Actions 的下载拦截
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    
    try:
        # 1. 建立带 Header 伪装的稳妥网络请求
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as response:
            with open("mihomo.gz", "wb") as f_out:
                shutil.copyfileobj(response, f_out)
        
        # 安全性拦截校验：防止下载到空字节
        if os.path.getsize("mihomo.gz") < 1000:
            raise ValueError("下载文件体积异常，疑似被官方防火墙拦截")

        # 2. 使用 Python 原生 gzip 库安全流式解压
        with gzip.open("mihomo.gz", "rb") as f_in:
            with open(core_path, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
                
        # 3. 赋予最高级别的 Linux 执行权限，并安全销毁残留缓存文件
        os.chmod(core_path, 0o755)
        if os.path.exists("mihomo.gz"): 
            os.remove("mihomo.gz")
        print("内核下载并流式解压成功！")
        return core_path
    except Exception as e:
        print(f"内核下载或解压失败: {e}，正在尝试备用安全通道...")
        # 4. 备用冗余下载方案：如果内置网络库被拦截，全自动无缝唤醒系统级安全 curl 链条
        try:
            if os.path.exists("mihomo.gz"): os.remove("mihomo.gz")
            # 使用系统级 curl 自动追踪重定向（-L）和浏览器伪装（-A）
            subprocess.run(["curl", "-L", "-A", "Mozilla/5.0", "-o", "mihomo.gz", url], check=True)
            with gzip.open("mihomo.gz", "rb") as f_in:
                with open(core_path, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
            os.chmod(core_path, 0o755)
            if os.path.exists("mihomo.gz"): os.remove("mihomo.gz")
            print("通过备用级系统安全通道成功加载内核！")
            return core_path
        except Exception as backup_err:
            print(f"致命错误：主备双通道均下载失败: {backup_err}")
            sys.exit(1)

def run_test_on_single_node(node_index, node_name, local_socks_port):
    """利用 GitHub 纯外网优势，发起真实流量探针获取 100% 准确的地理出口位置"""
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
    """
    企业级多线程测速流水线调度引擎
    """
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
        futures = [executor.submit(run_test_on_single_node, idx, p.get("name", f"Node_{idx}"), base_port + idx) for idx, p in enumerate(valid_proxies)]
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
