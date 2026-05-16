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
    """使用多冗余全球镜像镜像源 + 浏览器头混淆，彻底刺穿 GitHub Action 官方直连下载阻断"""
    core_path = "./mihomo"
    if os.path.exists(core_path):
        return core_path
    
    print("正在通过全球高可用加速镜像源加载轻量级测速内核...")
    
    # 构建高弹性的冗余镜像链条（当主官方链接人机拦截时，自动无缝轮询高速 CDN 集群）
    urls = [
        "https://ghproxy.com",
        "https://ghfast.top",
        "https://github.com"
    ]
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    
    success = False
    for url in urls:
        try:
            if os.path.exists("mihomo.gz"): os.remove("mihomo.gz")
            print(f"正在尝试拉取通道: {url}")
            
            # 使用原生 urllib 注入伪装头
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=20) as response:
                with open("mihomo.gz", "wb") as f_out:
                    shutil.copyfileobj(response, f_out)
            
            # 严格拦截校验：小于 1MB (1000000 字节) 的文件绝对是拦截网页或干扰空文本，直接抛出异常切入下一条镜像
            if os.path.exists("mihomo.gz") and os.path.getsize("mihomo.gz") < 1000000:
                raise ValueError("抓取到人机验证拦截页面，并非有效二进制流")
                
            # 3. 通过原生标准流式解压
            with gzip.open("mihomo.gz", "rb") as f_in:
                with open(core_path, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            os.chmod(core_path, 0o755)
            if os.path.exists("mihomo.gz"): os.remove("mihomo.gz")
            print("🎉 恭喜！内核已通过高速分发集群全自动加载成功！")
            success = True
            return core_path
        except Exception as err:
            print(f"当前节点加载失败: {err}，正在自动挂载后备节点...")
            continue
            
    if not success:
        print("警告：全量网络库管道被阻断，正在激活最终系统级网络穿透卷轴 (curl-tunnel)...")
        for url in urls:
            try:
                if os.path.exists("mihomo.gz"): os.remove("mihomo.gz")
                # -L 自动追踪重定向，-A 伪装浏览器，--retry 失败重试
                subprocess.run(["curl", "-L", "-A", "Mozilla/5.0", "--retry", "2", "-o", "mihomo.gz", url], check=True)
                if os.path.exists("mihomo.gz") and os.path.getsize("mihomo.gz") > 1000000:
                    with gzip.open("mihomo.gz", "rb") as f_in:
                        with open(core_path, "wb") as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    os.chmod(core_path, 0o755)
                    if os.path.exists("mihomo.gz"): os.remove("mihomo.gz")
                    print("🎉 终极系统穿透管道加载核心成功！")
                    return core_path
            except:
                continue
                
        print("致命缺陷：全球加速镜像集群与虚拟机级本地 curl 管道已被环境死锁，请检查网络权限。")
        sys.exit(1)

def run_test_on_single_node(node_index, node_name, local_socks_port):
    """探针：并发捕获100%精准的底层物理出口位置"""
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
