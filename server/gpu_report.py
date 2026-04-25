"""GPU 使用量报告模块 —— 与 dashboard 实时监控路径完全隔离。"""
import json
import os
import time
import logging
from datetime import datetime, timedelta

from flask import Blueprint, render_template, jsonify, request, current_app
from sqlalchemy import event

import markdown as _md
import bleach

from auth import login_required
from server import db, Client, client_realtime_data

logger = logging.getLogger('system_monitor_server')

# ─── Blueprint ────────────────────────────────────────────────────────────────

gpu_report_bp = Blueprint('gpu_report', __name__, url_prefix='/gpu-report',
                          template_folder='templates')

# ─── Data Models ──────────────────────────────────────────────────────────────

class GpuHourlyUsage(db.Model):
    """每小时 GPU 指标快照,保留 7 天,与 dashboard 实时数据隔离。"""
    __tablename__ = 'gpu_hourly_usage'

    id              = db.Column(db.Integer, primary_key=True)
    client_id       = db.Column(db.String(36),
                                db.ForeignKey('client.id', ondelete='CASCADE'),
                                nullable=False)
    gpu_index       = db.Column(db.Integer, nullable=False)
    hour            = db.Column(db.DateTime, nullable=False)   # 小时起始,本地时区
    gpu_name        = db.Column(db.String(100))
    vram_pct_avg    = db.Column(db.Float, default=0.0)
    vram_pct_peak   = db.Column(db.Float, default=0.0)
    util_pct_avg    = db.Column(db.Float, default=0.0)
    util_pct_peak   = db.Column(db.Float, default=0.0)
    ok_sample_count = db.Column(db.Integer, default=0)
    error_count     = db.Column(db.Integer, default=0)

    __table_args__ = (
        db.UniqueConstraint('client_id', 'gpu_index', 'hour',
                            name='uq_gpu_hourly'),
        db.Index('ix_gpu_hourly_hour', 'hour'),
    )


class LlmReport(db.Model):
    """LLM 周摘要记录,保留最近 12 条。"""
    __tablename__ = 'llm_report'

    id           = db.Column(db.Integer, primary_key=True)
    generated_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    period_start = db.Column(db.DateTime, nullable=False)
    period_end   = db.Column(db.DateTime, nullable=False)
    model        = db.Column(db.String(80))
    status       = db.Column(db.String(20), default='ok')   # ok | error
    content      = db.Column(db.Text)
    input_tokens  = db.Column(db.Integer)
    output_tokens = db.Column(db.Integer)

    __table_args__ = (db.Index('ix_llm_report_generated_at', 'generated_at'),)


# ─── Config ───────────────────────────────────────────────────────────────────

def load_gpu_report_config(config_parser=None):
    defaults = {
        'retention_days': 7,
        'idle_vram_threshold': 15,
        'heatmap_low_threshold': 20,
        'heatmap_high_threshold': 70,
        'longterm_vram_threshold': 20,
        'longterm_hours_required': 120,
        'llm_model': 'claude-haiku-4-5-20251001',
        'llm_schedule_cron': '0 9 * * 1',
        'llm_report_retention': 12,
        'timezone': '',
    }
    if config_parser is None or 'gpu_report' not in config_parser:
        return defaults
    section = config_parser['gpu_report']
    result = {}
    for k, v in defaults.items():
        if k in section and section[k]:
            try:
                result[k] = type(v)(section[k])
            except (ValueError, TypeError):
                result[k] = v
        else:
            result[k] = v
    return result


def _get_cfg():
    return current_app.config.get('GPU_REPORT', {
        'retention_days': 7,
        'idle_vram_threshold': 15,
        'heatmap_low_threshold': 20,
        'heatmap_high_threshold': 70,
        'longterm_vram_threshold': 20,
        'longterm_hours_required': 120,
        'llm_model': 'claude-haiku-4-5-20251001',
        'llm_report_retention': 12,
    })


# ─── Ingest ───────────────────────────────────────────────────────────────────

def ingest_hourly_sample(client_id: str, gpu: dict, now: datetime) -> None:
    """每次 /report 对每张 GPU 调用一次;不在本函数内 commit。"""
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


# ─── Cleanup Jobs ─────────────────────────────────────────────────────────────

def cleanup_hourly():
    cfg = _get_cfg()
    cutoff = datetime.now() - timedelta(days=cfg['retention_days'])
    deleted = GpuHourlyUsage.query.filter(GpuHourlyUsage.hour < cutoff).delete()
    db.session.commit()
    logger.info(f"GPU 小时数据清理: 删除 {deleted} 行(早于 {cutoff.date()})")


def cleanup_llm_reports():
    cfg = _get_cfg()
    keep = max(1, int(cfg.get('llm_report_retention', 12)))  # 防御:绝不全删
    ids_to_keep = [r.id for r in
                   LlmReport.query.order_by(LlmReport.generated_at.desc()).limit(keep).all()]
    if ids_to_keep:
        deleted = (LlmReport.query
                   .filter(~LlmReport.id.in_(ids_to_keep))
                   .delete(synchronize_session=False))
    else:
        # 没有 row to keep(空表),什么都不做
        deleted = 0
    db.session.commit()
    logger.info(f"LLM 摘要清理: 保留最近 {keep} 条,删除 {deleted} 条")


def _run_in_context(app, func):
    with app.app_context():
        try:
            func()
        except Exception as e:
            logger.error(f"scheduled job {func.__name__} 失败: {e}")
            try:
                db.session.rollback()
            except Exception as rb_err:
                logger.error(f"session rollback 失败: {rb_err}")


# ─── Scheduler ────────────────────────────────────────────────────────────────

_scheduler = None


def init_scheduler(app):
    global _scheduler
    if _scheduler is not None:
        return _scheduler
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        from tzlocal import get_localzone
    except ImportError:
        logger.warning("APScheduler 或 tzlocal 未安装,跳过调度任务初始化")
        return None

    cfg = app.config.get('GPU_REPORT', {})
    tz_name = cfg.get('timezone', '')
    try:
        tz = tz_name if tz_name else get_localzone()
    except Exception:
        tz = 'UTC'

    _scheduler = BackgroundScheduler(timezone=tz)
    _scheduler.add_job(lambda: _run_in_context(app, cleanup_hourly),
                       'cron', minute=5, id='cleanup_hourly')
    _scheduler.add_job(lambda: _run_in_context(app, cleanup_llm_reports),
                       'cron', day_of_week='sun', hour=3, id='cleanup_llm')
    _scheduler.add_job(lambda: _run_in_context(app, generate_llm_summary),
                       'cron', day_of_week='mon', hour=9, id='llm_summary')
    _scheduler.start()
    logger.info("APScheduler 已启动")
    return _scheduler


# ─── LLM Summary ─────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
你是实验室 GPU 资源使用情况的分析助手。输入是结构化 JSON,请输出简洁的 markdown 周报(< 400 字)。

必须覆盖:
1. 整体利用率趋势(上升/下降/稳定)
2. 长期空闲 GPU(VRAM 均值 < 20% 且低占用小时数 ≥ 120 的卡)
3. 硬件异常(error 样本 > 0 的卡)
4. 可立即调度的卡数量

禁止:
- 不要点名批评任何使用者
- 不要猜测使用者意图
- 不要使用"占卡""嫌疑""浪费"等负面字眼
- 不要输出 JSON,只输出 markdown 正文
"""


def _weighted_avg(rows, attr):
    total_ok = sum(r.ok_sample_count or 0 for r in rows)
    if total_ok == 0:
        return 0.0
    return sum(getattr(r, attr) * (r.ok_sample_count or 0) for r in rows) / total_ok


def build_llm_payload(now: datetime, cfg: dict) -> dict:
    period_end   = now.replace(hour=0, minute=0, second=0, microsecond=0)
    period_start = period_end - timedelta(days=7)
    low_vram_threshold = cfg.get('longterm_vram_threshold', 20)

    all_rows = (GpuHourlyUsage.query
                .filter(GpuHourlyUsage.hour >= period_start)
                .filter(GpuHourlyUsage.hour < period_end)
                .all())
    grouped: dict = {}
    for r in all_rows:
        grouped.setdefault((r.client_id, r.gpu_index), []).append(r)

    clients_data = []
    for client in Client.query.order_by(Client.display_order).all():
        gpu_stats = []
        for (cid, gidx), row_list in grouped.items():
            if cid != client.id:
                continue
            gpu_stats.append({
                'idx': gidx,
                'name': row_list[-1].gpu_name,
                'vram_avg_7d': round(_weighted_avg(row_list, 'vram_pct_avg'), 1),
                'util_avg_7d': round(_weighted_avg(row_list, 'util_pct_avg'), 1),
                'hours_observed': len(row_list),
                'hours_low_vram': sum(1 for r in row_list
                                      if (r.ok_sample_count or 0) > 0
                                      and r.vram_pct_avg < low_vram_threshold),
                'errors': sum(r.error_count or 0 for r in row_list),
            })
        if gpu_stats:
            clients_data.append({'host': client.hostname, 'gpus': gpu_stats})

    # 简单汇总
    rt = client_realtime_data
    now_t = datetime.now()
    online_clients = sum(
        1 for c in Client.query.all()
        if c.last_seen and (now_t - c.last_seen).total_seconds() < 600
    )
    idle_threshold = cfg.get('idle_vram_threshold', 15)
    idle_count = sum(
        1
        for c in Client.query.all()
        for g in rt.get(c.id, {}).get('gpu', [])
        if g.get('status', 'ok') != 'error'
        and g.get('memory_total', 0) > 0
        and g['memory_used'] / g['memory_total'] * 100 < idle_threshold
    )

    return {
        'period': f"{period_start.date()} ~ {period_end.date()}",
        'clients': clients_data,
        'summary_stats': {
            'total_clients': Client.query.count(),
            'online_clients': online_clients,
            'currently_free': idle_count,
        },
    }


def build_llm_payload_with_period(now: datetime, cfg: dict):
    """Same as build_llm_payload but also returns the period datetimes for DB row."""
    period_end = now.replace(hour=0, minute=0, second=0, microsecond=0)
    period_start = period_end - timedelta(days=7)
    payload = build_llm_payload(now, cfg)
    return payload, period_start, period_end


def generate_llm_summary():
    api_key = os.environ.get('ANTHROPIC_API_KEY')
    if not api_key:
        logger.warning("ANTHROPIC_API_KEY 未设置,跳过 LLM 周报生成")
        return

    cfg = _get_cfg()
    payload, period_start_dt, period_end_dt = build_llm_payload_with_period(
        datetime.now(), cfg)
    payload_json = json.dumps(payload, ensure_ascii=False, indent=2)

    try:
        import anthropic
    except ImportError:
        logger.warning("anthropic SDK 未安装,跳过 LLM 周报")
        return

    client = anthropic.Anthropic(api_key=api_key)
    last_err = None

    for attempt in range(3):
        try:
            resp = client.messages.create(
                model=cfg.get('llm_model', 'claude-haiku-4-5-20251001'),
                max_tokens=800,
                system=[{
                    "type": "text",
                    "text": _SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }],
                messages=[{
                    "role": "user",
                    "content": f"请分析以下过去一周的 GPU 使用数据,生成中文周报。\n\n数据:\n{payload_json}",
                }],
            )
            content = "".join(b.text for b in resp.content if b.type == 'text')
            db.session.add(LlmReport(
                generated_at=datetime.now(),
                period_start=period_start_dt,
                period_end=period_end_dt,
                model=cfg.get('llm_model'),
                status='ok',
                content=content,
                input_tokens=resp.usage.input_tokens,
                output_tokens=resp.usage.output_tokens,
            ))
            db.session.commit()
            logger.info(f"LLM 周报生成成功 {resp.usage.input_tokens}in/{resp.usage.output_tokens}out")
            return
        except Exception as e:
            last_err = e
            logger.warning(f"LLM 调用第 {attempt + 1} 次失败: {e}")
            if attempt < 2:
                time.sleep([60, 300][attempt])

    db.session.add(LlmReport(
        generated_at=datetime.now(),
        period_start=period_start_dt,
        period_end=period_end_dt,
        model=cfg.get('llm_model'),
        status='error',
        content=f"{type(last_err).__name__}: {last_err}",
    ))
    db.session.commit()
    logger.error(f"LLM 周报生成全部重试失败: {last_err}")


# ─── Markdown renderer ────────────────────────────────────────────────────────

_ALLOWED_TAGS = [
    'p', 'h1', 'h2', 'h3', 'h4', 'ul', 'ol', 'li',
    'strong', 'em', 'code', 'pre', 'blockquote', 'br', 'hr',
]


def render_markdown_safe(text: str) -> str:
    if not text:
        return ''
    html = _md.markdown(text, extensions=['extra'])
    return bleach.clean(html, tags=_ALLOWED_TAGS, strip=True)


# ─── Query helpers ────────────────────────────────────────────────────────────

def get_summary_stats():
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


def _classify_cell(vram_avg, low_t, high_t):
    if vram_avg < low_t:
        return 'low'
    if vram_avg < high_t:
        return 'mid'
    return 'high'


def get_heatmap_data(days=7):
    """Returns machine → GPUs hierarchy with per-machine rollup row.

    Machine rollup = max(vram_avg) across that machine's GPUs in each hour.
    If any GPU shows error (ok=0, err>0) for an hour, rollup is 'error'.
    Default UX: machines collapsed, click to expand per-GPU rows.
    """
    now = datetime.now()
    hour_end   = now.replace(minute=0, second=0, microsecond=0)
    hour_start = hour_end - timedelta(hours=days * 24)

    rows = (db.session.query(GpuHourlyUsage, Client.hostname,
                              Client.display_name, Client.display_order)
            .join(Client, GpuHourlyUsage.client_id == Client.id)
            .filter(GpuHourlyUsage.hour >= hour_start)
            .filter(GpuHourlyUsage.hour < hour_end)
            .all())

    # Group by (client, gpu) for per-card cells
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
    cfg = _get_cfg()
    low_t  = cfg['heatmap_low_threshold']
    high_t = cfg['heatmap_high_threshold']

    def _gpu_cell(usage, h):
        if usage is None:
            return {'hour': h.isoformat(), 'status': 'nodata',
                    'vram_avg': None, 'util_avg': None, 'ok': 0, 'err': 0}
        if (usage.ok_sample_count or 0) == 0:
            return {'hour': h.isoformat(), 'status': 'error',
                    'vram_avg': None, 'util_avg': None,
                    'ok': 0, 'err': usage.error_count or 0}
        v = round(usage.vram_pct_avg, 1)
        return {'hour': h.isoformat(),
                'status': _classify_cell(v, low_t, high_t),
                'vram_avg': v, 'util_avg': round(usage.util_pct_avg, 1),
                'vram_peak': round(usage.vram_pct_peak, 1),
                'ok': usage.ok_sample_count or 0,
                'err': usage.error_count or 0}

    # Build per-machine structure
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
        m['gpus'][gidx] = {
            'gpu_index': gidx,
            'gpu_name': latest_name,
            'cells': [_gpu_cell(cells_by_hour.get(h), h) for h in hours],
        }

    # Per-machine rollup row: max of each gpu's cell.vram_avg per hour
    machines = []
    for cid, m in machines_dict.items():
        gpus_sorted = [m['gpus'][gidx] for gidx in sorted(m['gpus'])]
        rollup_cells = []
        for hi, h in enumerate(hours):
            gpu_cells_at_h = [g['cells'][hi] for g in gpus_sorted]
            vram_vals = [c['vram_avg'] for c in gpu_cells_at_h if c['vram_avg'] is not None]
            err_vals  = [c['err']      for c in gpu_cells_at_h if c['err']]
            if vram_vals:
                v = max(vram_vals)
                rollup_cells.append({
                    'hour': h.isoformat(),
                    'status': _classify_cell(v, low_t, high_t),
                    'vram_avg': v,
                    'gpus_observed': len(gpu_cells_at_h),
                    'err_total': sum(err_vals),
                })
            elif err_vals:
                rollup_cells.append({
                    'hour': h.isoformat(), 'status': 'error',
                    'vram_avg': None, 'gpus_observed': len(gpu_cells_at_h),
                    'err_total': sum(err_vals),
                })
            else:
                rollup_cells.append({
                    'hour': h.isoformat(), 'status': 'nodata',
                    'vram_avg': None, 'gpus_observed': len(gpu_cells_at_h),
                    'err_total': 0,
                })

        machines.append({
            'client_id': cid,
            'hostname': m['hostname'],
            'display_name': m['display_name'],
            'gpu_count': len(gpus_sorted),
            'rollup_cells': rollup_cells,
            'gpus': gpus_sorted,
        })

    machines.sort(key=lambda m: machine_meta[m['client_id']]['display_order'])

    return {'hour_start': hour_start.isoformat(),
            'hour_end': hour_end.isoformat(),
            'hours': days * 24,
            'machines': machines}


def get_longterm_idle():
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

        client = Client.query.get(cid)
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
        client = Client.query.get(cid)
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


# ─── Routes ───────────────────────────────────────────────────────────────────

@gpu_report_bp.route('/')
@login_required
def report_page():
    latest_ok = (LlmReport.query
                 .filter_by(status='ok')
                 .order_by(LlmReport.generated_at.desc())
                 .first())
    latest_html = render_markdown_safe(latest_ok.content) if latest_ok else None

    history_rows = (LlmReport.query
                    .order_by(LlmReport.generated_at.desc())
                    .limit(12).all())
    history = [
        {
            'generated_at': r.generated_at,
            'status': r.status,
            'html': render_markdown_safe(r.content) if r.status == 'ok' else None,
            'error': r.content if r.status == 'error' else None,
        }
        for r in history_rows
    ]

    return render_template(
        'gpu_report.html',
        summary_stats=get_summary_stats(),
        idle_gpus=get_idle_gpus(),
        heatmap=get_heatmap_data(days=7),
        longterm_idle=get_longterm_idle(),
        error_gpus=get_error_gpus(),
        latest_summary=latest_ok,
        latest_summary_html=latest_html,
        history=history,
    )


@gpu_report_bp.route('/api/heatmap.json')
@login_required
def api_heatmap():
    days = int(request.args.get('days', 7))
    return jsonify(get_heatmap_data(days=days))


@gpu_report_bp.route('/api/idle.json')
@login_required
def api_idle():
    return jsonify({'timestamp': datetime.now().isoformat(),
                    'idle_gpus': get_idle_gpus()})
