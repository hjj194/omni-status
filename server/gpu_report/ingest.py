"""客户端 /report 调用时的小时聚合写入。"""
from datetime import datetime

from server import db

from .models import GpuHourlyUsage, GpuUserHourlyUsage


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

    必填字段缺失/类型错误时静默跳过(向后兼容老 client 上报半成品)。
    不在本函数内 commit;调用方负责 commit/rollback。
    """
    user = proc.get('user') or proc.get('user_name')
    if not user:
        user = '__unknown__'
    try:
        gpu_index = int(proc.get('gpu_index', 0))
        mem_mb    = float(proc.get('mem_mb', 0) or 0)
        util_pct  = float(proc.get('util_pct', 0) or 0)
    except (TypeError, ValueError):
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
