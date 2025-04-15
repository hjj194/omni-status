#!/usr/bin/env python3
import os
import time
import json
import socket
import platform
import psutil
import requests
import uuid
import logging
from datetime import datetime
import subprocess
import configparser
import sys

# 检查配置文件路径
CONFIG_FILE = '/etc/system-monitor/client.conf'
CLIENT_ID_FILE = '/etc/system-monitor/.client_id'
LOG_FILE = '/var/log/system-monitor/client.log'

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename=LOG_FILE
)
logger = logging.getLogger('client_monitor')

# 默认配置
DEFAULT_CONFIG = {
    'server': {
        'url': 'http://localhost:5000/report',
        'report_interval': '60'
    }
}

# 读取配置
def load_config():
    config = configparser.ConfigParser()
    
    # 如果配置文件不存在，创建默认配置
    if not os.path.exists(CONFIG_FILE):
        logger.warning(f"配置文件不存在，使用默认配置: {CONFIG_FILE}")
        config.read_dict(DEFAULT_CONFIG)
        return config
    
    try:
        config.read(CONFIG_FILE)
        logger.info(f"已加载配置文件: {CONFIG_FILE}")
        return config
    except Exception as e:
        logger.error(f"读取配置文件时出错: {e}")
        logger.warning("使用默认配置")
        config.read_dict(DEFAULT_CONFIG)
        return config

# 获取或创建客户端ID
def get_client_id():
    if os.path.exists(CLIENT_ID_FILE):
        try:
            with open(CLIENT_ID_FILE, 'r') as f:
                return f.read().strip()
        except Exception as e:
            logger.error(f"读取客户端ID文件时出错: {e}")
    
    # 创建新ID
    client_id = str(uuid.uuid4())
    try:
        # 确保目录存在
        os.makedirs(os.path.dirname(CLIENT_ID_FILE), exist_ok=True)
        with open(CLIENT_ID_FILE, 'w') as f:
            f.write(client_id)
        logger.info(f"已创建新的客户端ID: {client_id}")
    except Exception as e:
        logger.error(f"创建客户端ID文件时出错: {e}")
    
    return client_id

def get_nvidia_gpu_info():
    """获取NVIDIA GPU信息"""
    try:
        result = subprocess.run(['nvidia-smi', '--query-gpu=name,utilization.gpu,memory.used,memory.total', 
                              '--format=csv,noheader,nounits'], 
                             capture_output=True, text=True, check=True)
        
        gpus = []
        for i, line in enumerate(result.stdout.strip().split('\n')):
            if line.strip():
                name, utilization, mem_used, mem_total = line.split(', ')
                gpus.append({
                    'index': i,
                    'name': name,
                    'utilization': float(utilization),
                    'memory_used': float(mem_used),
                    'memory_total': float(mem_total)
                })
        return gpus
    except (subprocess.SubprocessError, FileNotFoundError):
        logger.debug("未检测到NVIDIA GPU或nvidia-smi命令不可用")
        return []

def get_system_info(client_id):
    """收集系统信息"""
    # CPU信息
    cpu_usage = psutil.cpu_percent(interval=1)
    cpu_count = psutil.cpu_count()
    
    # 内存信息
    memory = psutil.virtual_memory()
    memory_usage = {
        'total': memory.total,
        'used': memory.used,
        'percent': memory.percent
    }
    
    # 系统启动时间
    boot_time = psutil.boot_time()
    uptime_seconds = time.time() - boot_time
    
    # 硬盘使用情况 - 只收集根目录和总体存储
    disks = []
    total_disk_space = 0
    total_disk_used = 0
    
    for part in psutil.disk_partitions(all=False):
        if os.name == 'nt' or part.fstype != 'squashfs':  # 避免Docker容器中的问题
            try:
                usage = psutil.disk_usage(part.mountpoint)
                total_disk_space += usage.total
                total_disk_used += usage.used
                
                # 只添加根目录的详细信息
                if part.mountpoint == '/' or (os.name == 'nt' and part.mountpoint == 'C:\\'):
                    disks.append({
                        'device': part.device,
                        'mountpoint': '/',  # 统一显示为根目录
                        'total': usage.total,
                        'used': usage.used,
                        'percent': usage.percent
                    })
            except PermissionError:
                logger.warning(f"没有权限访问挂载点: {part.mountpoint}")
            except Exception as e:
                logger.warning(f"获取磁盘信息时出错 ({part.mountpoint}): {e}")
    
    # 添加总存储信息
    if total_disk_space > 0:
        total_percent = (total_disk_used / total_disk_space) * 100
        disks.append({
            'device': 'Total',
            'mountpoint': 'Total',
            'total': total_disk_space,
            'used': total_disk_used,
            'percent': total_percent
        })
    
    # GPU信息
    gpu_info = get_nvidia_gpu_info()
    
    # 获取主机名和IP
    hostname = socket.gethostname()
    try:
        ip_address = socket.gethostbyname(socket.gethostname())
        # 如果返回回环地址，尝试获取实际IP
        if ip_address.startswith('127.'):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # 不需要实际连接
            s.connect(('8.8.8.8', 1))
            ip_address = s.getsockname()[0]
            s.close()
    except Exception:
        ip_address = "127.0.0.1"  # 无法获取IP时的默认值
        logger.warning("无法获取主机IP地址，使用默认地址")
    
    # 时间戳
    timestamp = datetime.now().isoformat()
    
    return {
        'client_id': client_id,
        'timestamp': timestamp,
        'hostname': hostname,
        'ip_address': ip_address,
        'platform': platform.platform(),
        'cpu': {
            'count': cpu_count,
            'usage_percent': cpu_usage
        },
        'memory': memory_usage,
        'disks': disks,
        'gpu': gpu_info,
        'uptime_seconds': uptime_seconds
    }

def report_to_server(server_url, data):
    """将数据发送到服务器"""
    try:
        response = requests.post(server_url, json=data, timeout=10)
        if response.status_code == 200:
            logger.info(f"数据成功上报到服务器，状态码: {response.status_code}")
            return True
        else:
            logger.error(f"服务器返回错误，状态码: {response.status_code}, 响应: {response.text}")
            return False
    except requests.RequestException as e:
        logger.error(f"上报数据时发生错误: {e}")
        return False

def main():
    # 加载配置
    config = load_config()
    server_url = config.get('server', 'url')
    report_interval = int(config.get('server', 'report_interval'))
    
    # 获取客户端ID
    client_id = get_client_id()
    
    logger.info(f"客户端监控服务启动，客户端ID: {client_id}")
    logger.info(f"服务器地址: {server_url}, 上报间隔: {report_interval}秒")
    
    # 如果是以测试模式运行
    if len(sys.argv) > 1 and sys.argv[1] == '--test':
        try:
            system_info = get_system_info(client_id)
            print(json.dumps(system_info, indent=2))
            print("\n尝试连接服务器...")
            success = report_to_server(server_url, system_info)
            if success:
                print("✅ 服务器连接成功！数据已上报。")
                return 0
            else:
                print("❌ 服务器连接失败！请检查网络和服务器地址。")
                return 1
        except Exception as e:
            print(f"❌ 测试时出错: {e}")
            return 1
    
    # 主循环
    while True:
        try:
            system_info = get_system_info(client_id)
            report_to_server(server_url, system_info)
        except Exception as e:
            logger.error(f"获取或上报系统信息时出错: {e}")
        
        time.sleep(report_interval)

if __name__ == "__main__":
    # 确保日志目录存在
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    sys.exit(main())
