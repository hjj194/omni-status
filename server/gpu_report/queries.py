"""GPU 报告页面要展示的几个聚合查询。

每个 ``get_*`` 函数返回模板 ready 的 dict / list,**不**直接渲染。
"""
import logging
from datetime import datetime, timedelta

from server import db, Client, client_realtime_data

from .config import _get_cfg
from .models import GpuHourlyUsage

logger = logging.getLogger('system_monitor_server')

_WEEKDAY_ZH = ['一', '二', '三', '四', '五', '六', '日']


def _classify_cell(vram_avg, low_t, high_t):
    if vram_avg < low_t:
        return 'low'
    if vram_avg < high_t:
        return 'mid'
    return 'high'


def _aggregate_to_days(hourly_cells, days, day_starts):
    """把 168 个小时 cell 折叠到 7 个日级 cell,保留 24h sparkline。"""
    daily = []
    cells_iter = iter(hourly_cells)
    for d in range(days):
        day_hours = [next(cells_iter) for _ in range(24)]
        vram_vals = [c['vram_avg'] for c in day_hours if c.get('vram_avg') is not None]
        err_total = sum(c.get('err', 0) or c.get('err_total', 0) for c in day_hours)
        ok_total  = sum(c.get('ok', 0) for c in day_hours)
        peak_vals = [c.get('vram_peak') for c in day_hours
                     if c.get('vram_peak') is not None]

        if vram_vals:
            cell = {
                'day': day_starts[d].strftime('%m-%d'),
                'weekday': _WEEKDAY_ZH[day_starts[d].weekday()],
                'date_iso': day_starts[d].date().isoformat(),
                'vram_max': round(max(vram_vals), 1),
                'vram_avg': round(sum(vram_vals) / len(vram_vals), 1),
                'vram_peak': round(max(peak_vals), 1) if peak_vals else None,
                'ok_total': ok_total,
                'err_total': err_total,
                'hours_observed': len(vram_vals),
                'sparkline': [c['vram_avg'] for c in day_hours],
                'status': None,  # 由调用方填
            }
        else:
            cell = {
                'day': day_starts[d].strftime('%m-%d'),
                'weekday': _WEEKDAY_ZH[day_starts[d].weekday()],
                'date_iso': day_starts[d].date().isoformat(),
                'vram_max': None,
                'vram_avg': None,
                'vram_peak': None,
                'ok_total': 0,
                'err_total': err_total,
                'hours_observed': 0,
                'sparkline': [None] * 24,
                'status': 'error' if err_total > 0 else 'nodata',
            }
        daily.append(cell)
    return daily


def get_summary_stats():
    """顶部 4 个 tile 的数字。"""
    now = datetime.now()
    cfg = _get_cfg()
    online = sum(
        1 for c in Client.query.all()
        if c.last_seen and (now - c.last_seen).total_seconds() < 600
    )
    idle_threshold = cfg['idle_vram_threshold']
    idle_count = 0
    total_gpus = 0
    for cid, rt in client_realtime_data.items():
        for g in rt.get('gpu', []):
            total_gpus += 1
            if g.get('status', 'ok') != 'error' and g.get('memory_total', 0) > 0:
                if g['memory_used'] / g['memory_total'] * 100 < idle_threshold:
                    idle_count += 1

    week_ago = now - timedelta(days=7)
    err_gpus = (db.session.query(GpuHourlyUsage.client_id, GpuHourlyUsage.gpu_index)
                .filter(GpuHourlyUsage.hour >= week_ago)
                .filter(GpuHourlyUsage.error_count > 0)
                .distinct()
                .count())

    return {
        'total_clients': Client.query.count(),
        'online_clients': online,
        'total_gpus': total_gpus,
        'idle_count': idle_count,
        'error_gpu_count': err_gpus,
    }


def get_idle_gpus():
    """实时 dashboard 数据里 VRAM < idle_threshold 的 GPU 列表。"""
    cfg = _get_cfg()
    threshold = cfg['idle_vram_threshold']
    now = datetime.now()

    # 一次性查出各卡最后一次高 VRAM 时间(用于"已空闲 Xh")
    week_ago = now - timedelta(days=7)
    busy_rows = (db.session.query(
        GpuHourlyUsage.client_id,
        GpuHourlyUsage.gpu_index,
        db.func.max(GpuHourlyUsage.hour).label('last_busy'),
    ).filter(GpuHourlyUsage.hour >= week_ago)
     .filter(GpuHourlyUsage.vram_pct_avg >= threshold)
     .group_by(GpuHourlyUsage.client_id, GpuHourlyUsage.gpu_index)
     .all())
    last_busy_map = {(r.client_id, r.gpu_index): r.last_busy for r in busy_rows}

    idle = []
    for client in Client.query.order_by(Client.display_order).all():
        if not client.last_seen or (now - client.last_seen).total_seconds() >= 600:
            continue
        rt = client_realtime_data.get(client.id, {})
        for gpu in rt.get('gpu', []):
            if gpu.get('status') == 'error':
                continue
            mem_total = gpu.get('memory_total', 0)
            if not mem_total:
                continue
            vram_pct = gpu['memory_used'] / mem_total * 100
            if vram_pct >= threshold:
                continue
            last_busy = last_busy_map.get((client.id, gpu.get('index', 0)))
            if last_busy:
                idle_minutes = int((now - last_busy).total_seconds() // 60)
            else:
                idle_minutes = int((now - client.last_seen).total_seconds() // 60)
            idle.append({
                'hostname': client.hostname,
                'display_name': client.display_name or client.hostname,
                'gpu_index': gpu.get('index', 0),
                'gpu_name': gpu.get('name', '?'),
                'vram_pct': round(vram_pct, 1),
                'idle_minutes': idle_minutes,
            })
    idle.sort(key=lambda x: -x['idle_minutes'])
    return idle


def get_heatmap_data(days=7):
    """machine → GPUs hierarchy with daily-aggregated rollup."""
    now = datetime.now()
    hour_end   = now.replace(minute=0, second=0, microsecond=0)
    hour_start = hour_end - timedelta(hours=days * 24)

    rows = (db.session.query(GpuHourlyUsage, Client.hostname,
                              Client.display_name, Client.display_order)
            .join(Client, GpuHourlyUsage.client_id == Client.id)
            .filter(GpuHourlyUsage.hour >= hour_start)
            .filter(GpuHourlyUsage.hour < hour_end)
            .all())

    per_gpu: dict = {}
    machine_meta: dict = {}
    for usage, hostname, display_name, display_order in rows:
        key = (usage.client_id, usage.gpu_index)
        bucket = per_gpu.setdefault(key, {})
        bucket[usage.hour] = usage
        if usage.client_id not in machine_meta:
            machine_meta[usage.client_id] = {
                'hostname': hostname,
                'display_name': display_name or hostname,
                'display_order': display_order,
            }

    hours = [hour_start + timedelta(hours=i) for i in range(days * 24)]
    day_starts = [hour_start + timedelta(days=d) for d in range(days)]
    cfg = _get_cfg()
    low_t  = cfg['heatmap_low_threshold']
    high_t = cfg['heatmap_high_threshold']

    def _gpu_hourly(usage, h):
        if usage is None:
            return {'hour': h.isoformat(), 'vram_avg': None,
                    'util_avg': None, 'vram_peak': None, 'ok': 0, 'err': 0}
        if (usage.ok_sample_count or 0) == 0:
            return {'hour': h.isoformat(), 'vram_avg': None,
                    'util_avg': None, 'vram_peak': None,
                    'ok': 0, 'err': usage.error_count or 0}
        return {'hour': h.isoformat(),
                'vram_avg': round(usage.vram_pct_avg, 1),
                'util_avg': round(usage.util_pct_avg, 1),
                'vram_peak': round(usage.vram_pct_peak, 1),
                'ok': usage.ok_sample_count or 0,
                'err': usage.error_count or 0}

    machines_dict: dict = {}
    for (cid, gidx), cells_by_hour in per_gpu.items():
        meta = machine_meta[cid]
        m = machines_dict.setdefault(cid, {
            'client_id': cid,
            'hostname': meta['hostname'],
            'display_name': meta['display_name'],
            'display_order': meta['display_order'],
            'gpus': {},
        })
        latest_name = next(
            (cells_by_hour[h].gpu_name for h in sorted(cells_by_hour, reverse=True)
             if cells_by_hour[h].gpu_name),
            f'GPU {gidx}',
        )
        gpu_hourly_cells = [_gpu_hourly(cells_by_hour.get(h), h) for h in hours]
        gpu_daily = _aggregate_to_days(gpu_hourly_cells, days, day_starts)
        for cell in gpu_daily:
            if cell['vram_max'] is not None:
                cell['status'] = _classify_cell(cell['vram_max'], low_t, high_t)
        m['gpus'][gidx] = {
            'gpu_index': gidx,
            'gpu_name': latest_name,
            'days': gpu_daily,
        }

    machines = []
    for cid, m in machines_dict.items():
        gpus_sorted = [m['gpus'][gidx] for gidx in sorted(m['gpus'])]
        # Machine rollup: per-day, take max(vram_max) across all GPUs
        rollup_days = []
        for di in range(days):
            day_cells = [g['days'][di] for g in gpus_sorted]
            vram_maxes = [c['vram_max'] for c in day_cells if c['vram_max'] is not None]
            err_total  = sum(c['err_total'] for c in day_cells)
            sparkline_max = []
            for hi in range(24):
                hour_vals = [c['sparkline'][hi] for c in day_cells
                             if c['sparkline'][hi] is not None]
                sparkline_max.append(max(hour_vals) if hour_vals else None)

            base = day_cells[0]
            if vram_maxes:
                v = max(vram_maxes)
                rollup_days.append({
                    'day': base['day'], 'weekday': base['weekday'],
                    'date_iso': base['date_iso'],
                    'vram_max': round(v, 1),
                    'vram_avg': round(
                        sum(c['vram_avg'] for c in day_cells if c['vram_avg'] is not None)
                        / max(1, sum(1 for c in day_cells if c['vram_avg'] is not None)),
                        1),
                    'err_total': err_total,
                    'gpus_observed': len(day_cells),
                    'sparkline': sparkline_max,
                    'status': _classify_cell(v, low_t, high_t),
                })
            else:
                rollup_days.append({
                    'day': base['day'], 'weekday': base['weekday'],
                    'date_iso': base['date_iso'],
                    'vram_max': None, 'vram_avg': None,
                    'err_total': err_total,
                    'gpus_observed': len(day_cells),
                    'sparkline': sparkline_max,
                    'status': 'error' if err_total > 0 else 'nodata',
                })

        machines.append({
            'client_id': cid,
            'hostname': m['hostname'],
            'display_name': m['display_name'],
            'gpu_count': len(gpus_sorted),
            'days': rollup_days,
            'gpus': gpus_sorted,
        })

    machines.sort(key=lambda m: machine_meta[m['client_id']]['display_order'])

    day_labels = [
        {'day': day_starts[d].strftime('%m-%d'),
         'weekday': _WEEKDAY_ZH[day_starts[d].weekday()],
         'date_iso': day_starts[d].date().isoformat(),
         'is_today': day_starts[d].date() == hour_end.date()}
        for d in range(days)
    ]

    return {'hour_start': hour_start.isoformat(),
            'hour_end': hour_end.isoformat(),
            'days': days,
            'day_labels': day_labels,
            'machines': machines}


def get_longterm_idle():
    """7 天 VRAM 长期低于阈值的 GPU(数据系统性未使用)。"""
    from .llm_agent import _weighted_avg

    cfg = _get_cfg()
    vram_threshold  = cfg['longterm_vram_threshold']
    hours_required  = cfg['longterm_hours_required']
    period_start    = datetime.now().replace(minute=0, second=0, microsecond=0) - timedelta(days=7)

    all_rows = (GpuHourlyUsage.query
                .filter(GpuHourlyUsage.hour >= period_start)
                .all())
    grouped: dict = {}
    for r in all_rows:
        grouped.setdefault((r.client_id, r.gpu_index), []).append(r)

    result = []
    for (cid, gidx), row_list in grouped.items():
        total_ok = sum(r.ok_sample_count or 0 for r in row_list)
        if total_ok == 0:
            continue
        vram_avg = _weighted_avg(row_list, 'vram_pct_avg')
        util_avg = _weighted_avg(row_list, 'util_pct_avg')
        low_hours = sum(1 for r in row_list
                        if (r.ok_sample_count or 0) > 0 and r.vram_pct_avg < vram_threshold)

        if vram_avg >= vram_threshold or low_hours < hours_required:
            continue

        client = db.session.get(Client, cid)
        if not client:
            continue
        result.append({
            'hostname': client.hostname,
            'display_name': client.display_name or client.hostname,
            'gpu_index': gidx,
            'gpu_name': row_list[-1].gpu_name,
            'vram_avg_7d': round(vram_avg, 1),
            'util_avg_7d': round(util_avg, 1),
            'low_hours': low_hours,
            'total_hours': len(row_list),
        })
    result.sort(key=lambda x: -x['low_hours'])
    return result


def get_error_gpus():
    """7 天内有 nvidia-smi 错误样本的 GPU 列表。"""
    week_ago = datetime.now() - timedelta(days=7)
    rows = (GpuHourlyUsage.query
            .filter(GpuHourlyUsage.hour >= week_ago)
            .filter(GpuHourlyUsage.error_count > 0)
            .all())
    grouped: dict = {}
    for r in rows:
        grouped.setdefault((r.client_id, r.gpu_index), []).append(r)

    result = []
    for (cid, gidx), rlist in grouped.items():
        client = db.session.get(Client, cid)
        if not client:
            continue
        total_err = sum(r.error_count or 0 for r in rlist)
        latest_row = max(rlist, key=lambda r: r.hour)
        rt = client_realtime_data.get(cid, {})
        latest_err = next(
            (g for g in rt.get('gpu', [])
             if g.get('index') == gidx and g.get('status') == 'error'),
            None,
        )
        result.append({
            'hostname': client.hostname,
            'display_name': client.display_name or client.hostname,
            'gpu_index': gidx,
            'gpu_name': latest_row.gpu_name,
            'err_hours': len(rlist),
            'err_samples': total_err,
            'latest_error': (latest_err or {}).get('error', ''),
        })
    result.sort(key=lambda x: -x['err_hours'])
    return result
