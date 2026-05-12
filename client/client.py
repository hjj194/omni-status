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
import concurrent.futures

# 客户端版本号(每次发布升级一次,服务端用它标识哪些机器待升级)
CLIENT_VERSION = '0511-1'

# 检查配置文件路径
CONFIG_FILE = '/etc/system-monitor/client.conf'
CLIENT_ID_FILE = '/etc/system-monitor/.client_id'
LOG_FILE = '/var/log/system-monitor/client.log'

# 配置日志（带轮转，最大 10MB，保留 3 份备份）
from logging.handlers import RotatingFileHandler

def _make_client_log_handler():
    for candidate in [LOG_FILE,
                      os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client.log')]:
        try:
            os.makedirs(os.path.dirname(candidate), exist_ok=True)
            h = RotatingFileHandler(candidate, maxBytes=10 * 1024 * 1024, backupCount=3)
            h.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
            return h
        except (PermissionError, OSError):
            continue
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    return h

_log_handler = _make_client_log_handler()
logging.basicConfig(level=logging.INFO, handlers=[_log_handler])
logger = logging.getLogger('client_monitor')

# nvidia-smi 可用性缓存：None=未检测, True=可用, False=不可用
_nvidia_available = None

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

def _parse_gpu_line(i: int, line: str) -> dict:
    """解析 nvidia-smi 单行输出;解析失败返回 status='error' 样本。"""
    try:
        name, utilization, mem_used, mem_total = line.split(', ')
        return {
            'index': i,
            'name': name.strip(),
            'status': 'ok',
            'utilization': float(utilization),
            'memory_used': float(mem_used),
            'memory_total': float(mem_total),
        }
    except (ValueError, IndexError) as e:
        name = line.split(', ')[0].strip() if ',' in line else f'GPU{i}'
        logger.warning(f"GPU {i} 解析失败: {line!r} -> {e}")
        return {
            'index': i,
            'name': name,
            'status': 'error',
            'error': line.strip(),
            'timestamp': datetime.now().isoformat(),
        }


def get_nvidia_gpu_info():
    """获取NVIDIA GPU信息（缓存可用性，避免重复 fork）。

    单张卡解析失败返回 status='error' 样本,不影响其他卡,也不锁定可用性缓存。
    """
    global _nvidia_available

    if _nvidia_available is False:
        return []

    try:
        result = subprocess.run(
            ['nvidia-smi', '--query-gpu=name,utilization.gpu,memory.used,memory.total',
             '--format=csv,noheader,nounits'],
            capture_output=True, text=True, check=True, timeout=5
        )
        _nvidia_available = True
    except FileNotFoundError:
        # nvidia-smi 不存在，永久标记（不可能自动出现）
        _nvidia_available = False
        logger.debug("未检测到NVIDIA GPU或nvidia-smi命令不可用")
        return []
    except (subprocess.SubprocessError, subprocess.TimeoutExpired):
        # 瞬时故障（驱动挂起/超时），不永久缓存，下次周期自动重试
        logger.warning("nvidia-smi 临时异常，跳过本次采集，下次周期重试")
        return []

    gpus = []
    for i, line in enumerate(result.stdout.strip().split('\n')):
        if line.strip():
            gpus.append(_parse_gpu_line(i, line))
    return gpus

# ─── 用户级 GPU 用量采集 ──────────────────────────────────────────────────
# 通过 nvidia-smi 列出 GPU 上的进程,按 (user, gpu_index) 聚合一次再上报。
# 仅裸机有效;容器内 PID namespace 隔离会导致 PID→user 映射失败,目前
# 已在方案中确认实验室全是裸机。

# 过滤掉的系统级用户(显卡上 X server / display manager 之类的"杂项")
_SYSTEM_USERS = frozenset({
    'root', 'gdm', 'lightdm', 'sddm', 'xorg',
    'nobody', 'systemd-resolve', 'messagebus',
})


def _pid_to_username(pid: int):
    """裸机环境下把 PID 翻译成登录用户名。

    优先级: /proc/<pid>/loginuid → /proc/<pid>/status 的 Uid 行。
    任何一步失败返回 None,调用方归类到 __unknown__。
    """
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return None
    try:
        with open(f'/proc/{pid}/loginuid', 'r') as f:
            loginuid = int(f.read().strip())
        if loginuid != (1 << 32) - 1:   # 4294967295 = "未设置"
            import pwd
            return pwd.getpwuid(loginuid).pw_name
    except (FileNotFoundError, PermissionError, KeyError, ValueError):
        pass
    try:
        with open(f'/proc/{pid}/status', 'r') as f:
            for line in f:
                if line.startswith('Uid:'):
                    uid = int(line.split()[1])
                    if uid < 1000:
                        return None    # 系统账户,忽略
                    import pwd
                    return pwd.getpwuid(uid).pw_name
    except (FileNotFoundError, PermissionError, KeyError, ValueError):
        pass
    return None


def _parse_compute_apps_output(text: str):
    """nvidia-smi --query-compute-apps=pid,used_memory,gpu_uuid 的解析。

    返回 [(pid, used_memory_mb, gpu_uuid), ...]
    """
    rows = []
    for line in text.strip().split('\n'):
        if not line.strip():
            continue
        parts = [p.strip() for p in line.split(',')]
        if len(parts) < 3:
            continue
        try:
            pid = int(parts[0])
            mem = float(parts[1])
            uuid_s = parts[2]
            rows.append((pid, mem, uuid_s))
        except (ValueError, IndexError):
            continue
    return rows


def _parse_pmon_output(text: str):
    """nvidia-smi pmon -c 1 -s u 的输出解析。

    pmon 输出形如(列宽对齐, # 开头是注释):
        # gpu        pid  type    sm   mem   enc   dec   command
        # Idx          #   C/G     %     %     %     %   name
            0      1234     C    45    20     0     0   python
            1      5678     C     0     0     0     0   python

    返回 {pid: util_pct, ...} (取 sm 列)
    """
    result = {}
    for line in text.strip().split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            pid = int(parts[1])
            sm  = parts[3]
            util = 0.0 if sm == '-' else float(sm)
            result[pid] = util
        except (ValueError, IndexError):
            continue
    return result


def _build_uuid_to_index():
    """单独跑一次 nvidia-smi 取 (index, uuid) 映射。

    被 get_gpu_process_info 调用一次。失败时返回空 dict,调用方负责跳过本次采集
    而不是错误地把所有进程归到 GPU 0。
    """
    try:
        result = subprocess.run(
            ['nvidia-smi', '--query-gpu=index,uuid', '--format=csv,noheader'],
            capture_output=True, text=True, check=True, timeout=5
        )
    except (FileNotFoundError, subprocess.SubprocessError, subprocess.TimeoutExpired):
        return {}
    mapping = {}
    for line in result.stdout.strip().split('\n'):
        parts = [p.strip() for p in line.split(',')]
        if len(parts) >= 2:
            try:
                mapping[parts[1]] = int(parts[0])
            except ValueError:
                continue
    return mapping


def get_gpu_process_info():
    """采集 GPU 上每个进程的 (user, gpu_index, mem_mb, util_pct)。

    流程:
      1. nvidia-smi --query-compute-apps 拿每进程显存 + 进程归属的 GPU UUID
      2. nvidia-smi pmon -c 1 -s u 拿每进程 SM 利用率
      3. PID → username (优先 loginuid,系统用户过滤)
      4. 按 (user, gpu_index) 聚合: 显存求和,利用率取 max
    返回 [{'user', 'gpu_index', 'mem_mb', 'util_pct'}, ...]

    nvidia-smi 不可用 / 没卡 / 没进程 → 返回 []。
    """
    if _nvidia_available is False:
        return []
    try:
        proc_result = subprocess.run(
            ['nvidia-smi',
             '--query-compute-apps=pid,used_memory,gpu_uuid',
             '--format=csv,noheader,nounits'],
            capture_output=True, text=True, check=True, timeout=5
        )
    except FileNotFoundError:
        return []
    except (subprocess.SubprocessError, subprocess.TimeoutExpired):
        logger.warning("nvidia-smi 进程查询失败,跳过本次用户级采集")
        return []

    apps = _parse_compute_apps_output(proc_result.stdout)
    if not apps:
        return []

    # UUID → index 映射如果失败,跳过这次采集而不是把所有进程错误归到 GPU 0。
    # 多卡机器上 GPU 0 错误聚合会让用户报表里某些卡假阴性,导师做调度决策时基于
    # 错的数据,比缺一次采集更糟。
    uuid_to_idx = _build_uuid_to_index()
    if not uuid_to_idx:
        logger.warning(
            "nvidia-smi UUID→index 映射查询失败,跳过本次用户级采集"
            " (避免将所有进程误归到 GPU 0)")
        return []

    try:
        pmon_result = subprocess.run(
            ['nvidia-smi', 'pmon', '-c', '1', '-s', 'u'],
            capture_output=True, text=True, check=True, timeout=5
        )
        pid_to_util = _parse_pmon_output(pmon_result.stdout)
    except (subprocess.SubprocessError, subprocess.TimeoutExpired,
            FileNotFoundError):
        # MIG / 旧驱动 / 权限不足 → pmon 可能拿不到,VRAM 数据还能用
        pid_to_util = {}

    agg: dict = {}    # (user, gpu_index) -> {'mem_mb', 'util_pct'}
    for pid, mem, gpu_uuid in apps:
        if gpu_uuid not in uuid_to_idx:
            # 进程引用了未知 UUID(可能是 MIG slice 或采集瞬间卡热插拔),跳过
            logger.debug(f"未知 GPU UUID {gpu_uuid},pid={pid} 跳过")
            continue
        user = _pid_to_username(pid)
        if user is None:
            user = '__unknown__'
        elif user in _SYSTEM_USERS:
            continue
        gpu_idx = uuid_to_idx[gpu_uuid]
        util = pid_to_util.get(pid, 0.0)
        key = (user, gpu_idx)
        if key not in agg:
            agg[key] = {'mem_mb': 0.0, 'util_pct': 0.0}
        agg[key]['mem_mb']   += mem
        agg[key]['util_pct'] = max(agg[key]['util_pct'], util)

    return [
        {'user': u, 'gpu_index': g,
         'mem_mb': round(v['mem_mb'], 1),
         'util_pct': round(v['util_pct'], 1)}
        for (u, g), v in agg.items()
    ]


def get_system_info(client_id):
    """收集系统信息"""
    # CPU信息（非阻塞，基于距上次调用的时间窗口计算）
    cpu_usage = psutil.cpu_percent(interval=None)
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
    
    # 线程池创建一次，避免每个分区都创建/销毁线程池的开销
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        for part in psutil.disk_partitions(all=False):
            if os.name == 'nt' or part.fstype not in ('squashfs', 'tmpfs', 'devtmpfs'):
                try:
                    # 带 3 秒超时，防止 NFS 等网络挂载点无响应时阻塞整个上报周期
                    future = executor.submit(psutil.disk_usage, part.mountpoint)
                    usage = future.result(timeout=3)

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
                except concurrent.futures.TimeoutError:
                    logger.warning(f"获取磁盘信息超时，跳过挂载点: {part.mountpoint}")
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
    # 用户级 GPU 进程信息(0511+):有卡才采,无卡返回 []
    gpu_processes = get_gpu_process_info() if gpu_info else []
    
    # 获取主机名和IP
    hostname = socket.gethostname()
    try:
        ip_address = socket.gethostbyname(socket.gethostname())
        # 如果返回回环地址，尝试获取实际IP
        if ip_address.startswith('127.'):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(('8.8.8.8', 1))
                ip_address = s.getsockname()[0]
    except Exception:
        ip_address = "127.0.0.1"  # 无法获取IP时的默认值
        logger.warning("无法获取主机IP地址，使用默认地址")
    
    # 时间戳
    timestamp = datetime.now().isoformat()
    
    return {
        'client_id': client_id,
        'client_version': CLIENT_VERSION,
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
        'gpu_processes': gpu_processes,
        'uptime_seconds': uptime_seconds
    }

def report_to_server(server_url, data, report_token=None):
    """将数据发送到服务器。

    若配置了 report_token,会自动以 Bearer 形式放进 Authorization 头。
    服务器侧不强制时无影响,强制时缺/错 token 会收到 401。
    """
    headers = {}
    if report_token:
        headers['Authorization'] = f'Bearer {report_token}'
    try:
        response = requests.post(server_url, json=data, timeout=10, headers=headers)
        if response.status_code == 200:
            # 成功上报降级为 DEBUG 避免日志噪音(每 60s 一次,长期会撑满 40MB 配额)
            logger.debug(f"数据成功上报到服务器，状态码: {response.status_code}")
            return True
        elif response.status_code == 401:
            logger.error("/report 鉴权失败:report_token 未配置或与服务端不匹配")
            return False
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
    # 可选共享密钥(服务端 server.conf [server] report_token 配了就要传)
    try:
        report_token = config.get('server', 'report_token')
    except Exception:
        report_token = os.environ.get('REPORT_TOKEN', '')
    if not report_token:
        report_token = os.environ.get('REPORT_TOKEN', '')

    # 获取客户端ID
    client_id = get_client_id()

    # 初始化 CPU 采样基准（首次调用返回值无意义，丢弃）
    psutil.cpu_percent(interval=None)

    logger.info(f"客户端监控服务启动，客户端ID: {client_id}")
    logger.info(f"服务器地址: {server_url}, 上报间隔: {report_interval}秒"
                f"{' (with report_token)' if report_token else ''}")

    # 如果是以测试模式运行
    if len(sys.argv) > 1 and sys.argv[1] == '--test':
        try:
            system_info = get_system_info(client_id)
            print(json.dumps(system_info, indent=2))
            print("\n尝试连接服务器...")
            success = report_to_server(server_url, system_info, report_token=report_token)
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
            report_to_server(server_url, system_info, report_token=report_token)
        except Exception as e:
            logger.error(f"获取或上报系统信息时出错: {e}")

        time.sleep(report_interval)

if __name__ == "__main__":
    # 确保日志目录存在
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    sys.exit(main())

