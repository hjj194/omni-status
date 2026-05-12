"""客户端 /report 调用时的小时聚合写入。"""
import logging
import re
from datetime import datetime

from server import db

from .models import GpuHourlyUsage, GpuUserHourlyUsage

logger = logging.getLogger('system_monitor_server')

# 接受的用户名字符集 — POSIX 标准 + 中文实验室常见的下划线/连字符。
# 拒绝任何含 HTML/SQL/控制字符的字符串(模板 auto-escape 已经防 XSS,
# 这里是 defense-in-depth + 防 CSV 公式注入根源)。32 字符上限避免日志/UI 膨胀。
_USERNAME_RE = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_\-.]{0,31}$')


def ingest_hourly_sample(client_id: str, gpu: dict, now: datetime) -> None:
    """每次 /report 对每张 GPU 调用一次;不在本函数内 commit。

    - status='ok' 走数值路径:更新 running mean + peak
    - status='error' 或 memory_total <= 0:仅累加 error_count
    - 旧客户端(无 status 字段)按 'ok' 处理
    """
    hour = now.replace(minute=0, second=0, microsecond=0)
    row = (GpuHourlyUsage.query
           .filter_by(client_id=client_id, gpu_index=gpu.get('index', 0), hour=hour)
           .first())
    if row is None:
        row = GpuHourlyUsage(
            client_id=client_id,
            gpu_index=gpu.get('index', 0),
            hour=hour,
        )
        db.session.add(row)

    if gpu.get('name'):
        row.gpu_name = gpu['name']

    status = gpu.get('status', 'ok')
    if status == 'error':
        row.error_count = (row.error_count or 0) + 1
        return

    mem_total = gpu.get('memory_total', 0)
    if mem_total is None or mem_total <= 0:
        row.error_count = (row.error_count or 0) + 1
        return

    vram_pct = gpu['memory_used'] / mem_total * 100
    util_pct = float(gpu.get('utilization', 0))
    n = row.ok_sample_count or 0
    prev_vram = row.vram_pct_avg or 0.0
    prev_util = row.util_pct_avg or 0.0

    row.vram_pct_avg  = (prev_vram * n + vram_pct) / (n + 1)
    row.util_pct_avg  = (prev_util * n + util_pct) / (n + 1)
    row.vram_pct_peak = max(row.vram_pct_peak or 0.0, vram_pct)
    row.util_pct_peak = max(row.util_pct_peak or 0.0, util_pct)
    row.ok_sample_count = n + 1


def ingest_user_hourly_sample(client_id: str, proc: dict, now: datetime) -> None:
    """每次 /report 对 payload['gpu_processes'] 里的每一项调用一次。

    proc 形如 {'user': 'alice', 'gpu_index': 0, 'mem_mb': 4096, 'util_pct': 35}。

    校验/防御逻辑:
    - user_name 不通过 POSIX 字符集校验 → 归类 __unknown__(防 CSV 公式注入/未来 XSS)
    - mem_mb / util_pct 是 None 或缺失 → 跳过样本(防止把数据收集 gap 当成 0 用量,
      会把用户均值人为压低,导致导师误判用户实际使用强度)
    - mem_mb 和 util_pct 都 ≤ 0 → 跳过(没意义的零样本)
    - 类型错误 → 记 warning 跳过(便于运维查出哪台 client 上报半成品)

    不在本函数内 commit;调用方负责 commit/rollback。
    """
    user_raw = proc.get('user') or proc.get('user_name')
    if user_raw and _USERNAME_RE.match(str(user_raw)):
        user = str(user_raw)
    else:
        if user_raw:
            logger.warning(
                f"非法 user_name {user_raw!r} 来自 client={client_id},"
                f" 归类 __unknown__")
        user = '__unknown__'

    # 严格区分 "缺失/None" 与 "真实零值"。
    # 旧版本用 `or 0` 把 None 当 0,导致采集 gap 被记成"用户均值 0 MB"。
    raw_mem  = proc.get('mem_mb')
    raw_util = proc.get('util_pct')
    if raw_mem is None or raw_util is None:
        logger.warning(
            f"gpu_processes 缺 mem_mb/util_pct from client={client_id}: {proc!r}")
        return
    try:
        gpu_index = int(proc.get('gpu_index', 0))
        mem_mb    = float(raw_mem)
        util_pct  = float(raw_util)
    except (TypeError, ValueError):
        logger.warning(
            f"gpu_processes 类型错误 from client={client_id}: {proc!r}")
        return

    # mem 和 util 都 ≤ 0 → 没意义的样本,跳过避免拉低 running mean
    if mem_mb <= 0 and util_pct <= 0:
        return

    hour = now.replace(minute=0, second=0, microsecond=0)
    row = (GpuUserHourlyUsage.query
           .filter_by(client_id=client_id, gpu_index=gpu_index,
                      user_name=user, hour=hour)
           .first())
    if row is None:
        row = GpuUserHourlyUsage(
            client_id=client_id,
            gpu_index=gpu_index,
            user_name=user,
            hour=hour,
        )
        db.session.add(row)

    n = row.sample_count or 0
    prev_vram = row.vram_mb_avg or 0.0
    prev_util = row.util_pct_avg or 0.0

    row.vram_mb_avg   = (prev_vram * n + mem_mb) / (n + 1)
    row.util_pct_avg  = (prev_util * n + util_pct) / (n + 1)
    row.vram_mb_peak  = max(row.vram_mb_peak or 0.0, mem_mb)
    row.util_pct_peak = max(row.util_pct_peak or 0.0, util_pct)
    row.sample_count  = n + 1
