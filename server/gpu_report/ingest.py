"""客户端 /report 调用时的小时聚合写入。"""
from datetime import datetime

from server import db

from .models import GpuHourlyUsage


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
