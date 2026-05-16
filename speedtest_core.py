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
    """使用 Python 原生流式解压，确保 100% 成功生成无依赖的 mihomo 核心二进制"""
    core_path = "./mihomo"
    if os.path.exists(core_path):
        return core_path
    
    print("正在从 GitHub 官方下载轻量级测速内核...")
    url = "https://github.com"
    try:
        # 1. 下载压缩包
        urllib.request.urlretrieve(url, "mihomo.gz")
        # 2. 绕过系统命令行，改用 Python 内置库直接进行二进制解压，绝不产生文件名不一致错误
        with gzip.open("mihomo.gz", "rb") as f_in:
            with open(core_path, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
                
        # 3. 赋予 Linux 环境下最高级别的安全执行权限，并销毁缓存
        os.chmod(core_path, 0o755)
        if os.path.exists("mihomo.gz"): 
            os.remove("mihomo.gz")
        return core_path
    except Exception as e:
        print(f"内核下载或解压失败: {e}")
        sys.exit(1)

def run_test_on_single_node(node_index, node_name, local_socks_port):
    """利用 GitHub 纯外网优势，发起真实流量探针获取 100% 准确的地理出口位置"""
    api_url = "http://ip-api.com"
    # 使用虚拟机自带的 curl 命令挂载本地代理端口进行探针测试，避免复杂的底层握手逻辑
    cmd = ["curl", "-s", "--socks5-hostname", f"127.0.0.1:{local_socks_port}", "--max-time", str(TIMEOUT), api_url]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0 and result.stdout:
            data = json.loads(result.stdout)
            if data.get("status") == "success":
                country = data.get("country", "未知")
                country_code = data.get("countryCode", "").upper()
                
                # 全面补齐主流及高频节点国旗 Emoji 字典
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
    
    # 动态为每个节点分配一个独立的本地 Socks5 监听端口，实现真正意义上的高并发
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
    
    # 生成静默测速专用的轻量化配置文件
    with open("speedtest_clash.yaml", "w", encoding="utf-8") as f:
        yaml.dump(temp_config, f, allow_unicode=True)
        
    print("正在启动后台测速隧道核心...")
    proc = subprocess.Popen([core_bin, "-f", "speedtest_clash.yaml"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)  # 给予内核充裕的初始化及握手就位时间
    
    print(f"开始并行测速校准（最大线程数: {MAX_WORKERS}）...")
    results = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(run_test_on_single_node, idx, p.get("name", f"Node_{idx}"), base_port + idx) for idx, p in enumerate(valid_proxies)]
        for future in futures:
            idx, label = future.result()
            if label:
                results[idx] = label
                
    # 彻底关闭后台常驻进程，彻底杜绝 GitHub 虚拟机产生内存泄漏
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        
    if os.path.exists("speedtest_clash.yaml"): 
        os.remove("speedtest_clash.yaml")
    
    # 清洗节点并重构全活节点的命名格式
    final_proxies = []
    for idx, p in enumerate(valid_proxies):
        if idx in results:
            real_label = results[idx]
            # 提取原名称中的数字序号，保留核心代号
            clean_num = re.sub(r'[^0-9]', '', p.get("name", ""))
            p["name"] = f"{real_label} {clean_num if clean_num else idx} @zmxooo"
            
            # 清理无用的临时识别干扰项，保证最终导出的 config.yaml 绝对纯净
            if "label" in p: del p["label"]
            if "raw_json" in p: del p["raw_json"]
            final_proxies.append(p)
            
    return final_proxies
