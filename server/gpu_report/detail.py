"""单机 / 单 GPU 详情页:168 小时趋势 + 统计 + 每卡分解。"""
import logging
from datetime import datetime, timedelta

from server import db, Client

from .config import _get_cfg
from .models import GpuHourlyUsage
from .queries import _WEEKDAY_ZH

logger = logging.getLogger('system_monitor_server')


def get_machine_detail(client_id, gpu_index=None, days=7):
    """Detailed 168-hour view for one machine (or single GPU within it).

    Returns hourly series suitable for SVG line-chart rendering, plus
    per-GPU breakdown and aggregate statistics.
    """
    client = db.session.get(Client, client_id)
    if client is None:
        return None

    now = datetime.now()
    hour_end   = now.replace(minute=0, second=0, microsecond=0)
    hour_start = hour_end - timedelta(hours=days * 24)

    q = (GpuHourlyUsage.query
         .filter_by(client_id=client_id)
         .filter(GpuHourlyUsage.hour >= hour_start)
         .filter(GpuHourlyUsage.hour < hour_end))
    if gpu_index is not None:
        q = q.filter_by(gpu_index=gpu_index)
    rows = q.all()

    if not rows and gpu_index is None:
        return {
            'client_id': client_id,
            'hostname': client.hostname,
            'display_name': client.display_name or client.hostname,
            'gpu_index': None,
            'gpu_name': None,
            'hour_start': hour_start.isoformat(),
            'hour_end': hour_end.isoformat(),
            'days': days,
            'series': [],
            'gpus': [],
            'stats': None,
            'day_labels': [],
        }

    hours = [hour_start + timedelta(hours=i) for i in range(days * 24)]

    by_gpu: dict = {}
    for r in rows:
        by_gpu.setdefault(r.gpu_index, {})[r.hour] = r

    gpus_out = []
    for gidx in sorted(by_gpu):
        cells_by_h = by_gpu[gidx]
        latest_name = next(
            (cells_by_h[h].gpu_name for h in sorted(cells_by_h, reverse=True)
             if cells_by_h[h].gpu_name),
            f'GPU {gidx}',
        )
        vram_series = []
        util_series = []
        err_series = []
        for h in hours:
            u = cells_by_h.get(h)
            if u is None or (u.ok_sample_count or 0) == 0:
                vram_series.append(None)
                util_series.append(None)
                err_series.append(u.error_count if u else 0)
            else:
                vram_series.append(round(u.vram_pct_avg, 1))
                util_series.append(round(u.util_pct_avg, 1))
                err_series.append(u.error_count or 0)
        gpus_out.append({
            'gpu_index': gidx,
            'gpu_name': latest_name,
            'vram_series': vram_series,
            'util_series': util_series,
            'err_series': err_series,
        })

    if gpu_index is not None:
        target = next((g for g in gpus_out if g['gpu_index'] == gpu_index), None)
        headline_vram = target['vram_series'] if target else [None] * len(hours)
        headline_util = target['util_series'] if target else [None] * len(hours)
        headline_label = (f'GPU {gpu_index} · {target["gpu_name"]}'
                          if target else f'GPU {gpu_index}')
    else:
        headline_vram = []
        headline_util = []
        for hi in range(len(hours)):
            v_vals = [g['vram_series'][hi] for g in gpus_out
                      if g['vram_series'][hi] is not None]
            u_vals = [g['util_series'][hi] for g in gpus_out
                      if g['util_series'][hi] is not None]
            headline_vram.append(max(v_vals) if v_vals else None)
            headline_util.append(max(u_vals) if u_vals else None)
        headline_label = f'{client.display_name or client.hostname} · 全机最高'

    valid_vram = [v for v in headline_vram if v is not None]
    valid_util = [u for u in headline_util if u is not None]
    cfg = _get_cfg()
    high_t = cfg['heatmap_high_threshold']
    low_t  = cfg['heatmap_low_threshold']
    busy_hours = sum(1 for v in valid_vram if v >= high_t)
    idle_hours = sum(1 for v in valid_vram if v < low_t)
    total_err = sum(g_['err_series'][hi]
                    for g_ in (gpus_out if gpu_index is None
                               else [g for g in gpus_out if g['gpu_index'] == gpu_index])
                    for hi in range(len(hours)))

    stats = {
        'observed_hours': len(valid_vram),
        'window_hours': len(hours),
        'vram_avg': round(sum(valid_vram) / len(valid_vram), 1) if valid_vram else None,
        'vram_peak': max(valid_vram) if valid_vram else None,
        'util_avg': round(sum(valid_util) / len(valid_util), 1) if valid_util else None,
        'util_peak': max(valid_util) if valid_util else None,
        'busy_hours': busy_hours,
        'idle_hours': idle_hours,
        'error_total': total_err,
    }

    day_labels = []
    for d in range(days):
        ds = hour_start + timedelta(days=d)
        day_labels.append({
            'day': ds.strftime('%m-%d'),
            'weekday': _WEEKDAY_ZH[ds.weekday()],
            'hour_offset': d * 24,
            'is_today': ds.date() == hour_end.date(),
        })

    return {
        'client_id': client_id,
        'hostname': client.hostname,
        'display_name': client.display_name or client.hostname,
        'gpu_index': gpu_index,
        'gpu_name': headline_label,
        'hour_start': hour_start.isoformat(),
        'hour_end': hour_end.isoformat(),
        'hours': [h.isoformat() for h in hours],
        'days': days,
        'series_vram': headline_vram,
        'series_util': headline_util,
        'gpus': gpus_out,
        'stats': stats,
        'day_labels': day_labels,
    }
