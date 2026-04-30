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

RUNTIME_SETTINGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                      'runtime_settings.json')

DEFAULT_CFG = {
    'retention_days': 7,                 # GpuHourlyUsage 保留天数
    'idle_vram_threshold': 15,
    'heatmap_low_threshold': 20,
    'heatmap_high_threshold': 70,
    'longterm_vram_threshold': 20,
    'longterm_hours_required': 120,
    'llm_model': 'claude-haiku-4-5-20251001',
    'llm_schedule_cron': '0 9 * * 1',
    'llm_report_retention': 12,
    'uptime_record_retention_days': 90,  # UptimeRecord 保留天数
    'timezone': '',
}

# Bounds for admin-configurable settings(防御性约束)
SETTING_BOUNDS = {
    'retention_days':              (1, 365),
    'llm_report_retention':        (1, 100),
    'uptime_record_retention_days': (30, 730),
}


def load_runtime_settings() -> dict:
    if not os.path.exists(RUNTIME_SETTINGS_FILE):
        return {}
    try:
        with open(RUNTIME_SETTINGS_FILE) as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"读取 runtime_settings.json 失败: {e}")
        return {}


def save_runtime_settings(updates: dict, app=None):
    current = load_runtime_settings()
    current.update(updates)
    tmp = RUNTIME_SETTINGS_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(current, f, indent=2, ensure_ascii=False)
    os.replace(tmp, RUNTIME_SETTINGS_FILE)
    if app is not None:
        # 立即同步到 app.config 让运行中的代码读到新值
        cfg = app.config.setdefault('GPU_REPORT', dict(DEFAULT_CFG))
        cfg.update(updates)
    logger.info(f"runtime_settings 已更新: {updates}")


def load_gpu_report_config(config_parser=None):
    defaults = dict(DEFAULT_CFG)
    if config_parser is not None and 'gpu_report' in config_parser:
        section = config_parser['gpu_report']
        for k, v in defaults.items():
            if k in section and section[k]:
                try:
                    defaults[k] = type(v)(section[k])
                except (ValueError, TypeError):
                    pass
    # 文件 < INI < runtime overrides(管理员面板写的)
    overrides = load_runtime_settings()
    for k, v in overrides.items():
        if k in defaults:
            try:
                defaults[k] = type(DEFAULT_CFG[k])(v)
            except (ValueError, TypeError):
                pass
    return defaults


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

    # 同时按配置清理 UptimeRecord 防止无限累积
    try:
        from server import UptimeRecord
        uptime_cutoff = (datetime.now() -
                         timedelta(days=cfg.get('uptime_record_retention_days', 90))).date()
        u_deleted = UptimeRecord.query.filter(UptimeRecord.date < uptime_cutoff).delete()
        if u_deleted > 0:
            db.session.commit()
            logger.info(f"UptimeRecord 清理: 删除 {u_deleted} 行(早于 {uptime_cutoff})")
    except Exception as e:
        logger.warning(f"UptimeRecord 清理失败: {e}")


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


_WEEKDAY_ZH = ['一', '二', '三', '四', '五', '六', '日']


def _aggregate_to_days(hourly_cells, days, day_starts):
    """Take 168 hourly cells → 7 daily cells (max + avg + sparkline 24h).

    Each daily cell carries the 24 hourly cells inside it for drill-down via
    the tooltip / click expansion. Sparkline = list of 24 numbers (vram_avg
    or null), suitable for SVG path rendering.
    """
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
                'status': None,  # set below
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


def get_heatmap_data(days=7):
    """Returns machine → GPUs hierarchy with daily-aggregated rollup.

    Cells are aggregated to one-per-day (7 cells) instead of one-per-hour
    (168) for visual clarity. Each daily cell carries a 24-element
    sparkline for drill-down,plus max/avg/peak/err summary.
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

    # Day-axis labels (shown once at the top of the heatmap)
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
        # Machine has no data at all in this window
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

    # Group by gpu_index
    by_gpu: dict = {}
    for r in rows:
        by_gpu.setdefault(r.gpu_index, {})[r.hour] = r

    def _hourly_value(usage):
        if usage is None or (usage.ok_sample_count or 0) == 0:
            return None, (usage.error_count if usage else 0)
        return round(usage.vram_pct_avg, 1), (usage.error_count or 0)

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

    # Build the headline series (max VRAM across all GPUs per hour for
    # machine view; just the single GPU's series for GPU view)
    if gpu_index is not None:
        target = next((g for g in gpus_out if g['gpu_index'] == gpu_index), None)
        headline_vram = target['vram_series'] if target else [None] * len(hours)
        headline_util = target['util_series'] if target else [None] * len(hours)
        headline_label = f'GPU {gpu_index} · {target["gpu_name"]}' if target else f'GPU {gpu_index}'
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

    # Aggregate stats over the window
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

    # Day-axis ticks
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


@gpu_report_bp.route('/detail/<client_id>')
@gpu_report_bp.route('/detail/<client_id>/<int:gpu_index>')
@login_required
def detail_page(client_id, gpu_index=None):
    detail = get_machine_detail(client_id, gpu_index=gpu_index, days=7)
    if detail is None:
        from flask import abort
        abort(404)
    return render_template('gpu_detail.html', detail=detail)


@gpu_report_bp.route('/api/detail/<client_id>.json')
@gpu_report_bp.route('/api/detail/<client_id>/<int:gpu_index>.json')
@login_required
def api_detail(client_id, gpu_index=None):
    detail = get_machine_detail(client_id, gpu_index=gpu_index,
                                days=int(request.args.get('days', 7)))
    if detail is None:
        return jsonify({'error': 'client not found'}), 404
    return jsonify(detail)


# ─── Storage stats & cleanup helpers ──────────────────────────────────────────

def _format_size(num_bytes: int) -> str:
    """1234 → '1.2 KB', 1234567 → '1.2 MB' etc."""
    if num_bytes is None:
        return '—'
    if num_bytes < 1024:
        return f'{num_bytes} B'
    if num_bytes < 1024 ** 2:
        return f'{num_bytes / 1024:.1f} KB'
    if num_bytes < 1024 ** 3:
        return f'{num_bytes / 1024 ** 2:.1f} MB'
    return f'{num_bytes / 1024 ** 3:.2f} GB'


def _table_byte_size(table_name: str) -> int:
    """Approximate bytes used by a single SQLite table (data + indexes)."""
    try:
        result = db.session.execute(db.text(
            "SELECT SUM(pgsize) FROM dbstat WHERE name = :n OR name LIKE :idx_pat"
        ), {'n': table_name, 'idx_pat': f'sqlite_autoindex_{table_name}_%'})
        v = result.scalar()
        if v is not None:
            return int(v)
    except Exception:
        pass
    # Fallback: rough estimate using row count × bytes-per-row
    return -1


def get_storage_stats():
    """Snapshot of disk + DB occupancy + row counts."""
    from sqlalchemy import inspect

    db_uri = current_app.config.get('SQLALCHEMY_DATABASE_URI', '')
    db_path = db_uri.replace('sqlite:///', '') if db_uri.startswith('sqlite:///') else None
    db_size = os.path.getsize(db_path) if db_path and os.path.exists(db_path) else None

    # Per-table row counts
    n_gpu_hourly = GpuHourlyUsage.query.count()
    n_llm_report = LlmReport.query.count()
    n_clients = Client.query.count()
    try:
        from server import UptimeRecord, Announcement, User
        n_uptime = UptimeRecord.query.count()
        n_announce = Announcement.query.count()
        n_users = User.query.count()
    except ImportError:
        n_uptime = n_announce = n_users = 0

    # Server log files (pattern: server.log + server.log.1..N)
    log_files = []
    log_total = 0
    for log_dir in ['/var/log/system-monitor',
                    os.path.dirname(os.path.abspath(__file__))]:
        if not os.path.isdir(log_dir):
            continue
        for name in sorted(os.listdir(log_dir)):
            if name.startswith('server.log'):
                full = os.path.join(log_dir, name)
                try:
                    sz = os.path.getsize(full)
                except OSError:
                    continue
                log_files.append({'name': name, 'path': full, 'size': sz,
                                   'is_active': name == 'server.log'})
                log_total += sz
        if log_files:
            break

    # In-memory realtime cache
    rt_count = len(client_realtime_data)

    return {
        'db_path': db_path,
        'db_size': db_size,
        'db_size_human': _format_size(db_size),
        'tables': [
            {'name': 'gpu_hourly_usage', 'label': 'GPU 小时聚合',
             'rows': n_gpu_hourly,
             'size': _table_byte_size('gpu_hourly_usage'),
             'cleanable': True, 'kind': 'gpu_hourly'},
            {'name': 'llm_report', 'label': 'LLM 周报',
             'rows': n_llm_report,
             'size': _table_byte_size('llm_report'),
             'cleanable': True, 'kind': 'llm_report'},
            {'name': 'uptime_record', 'label': '客户端可用性记录',
             'rows': n_uptime,
             'size': _table_byte_size('uptime_record'),
             'cleanable': True, 'kind': 'uptime'},
            {'name': 'client', 'label': '客户端注册信息',
             'rows': n_clients,
             'size': _table_byte_size('client'),
             'cleanable': False},
            {'name': 'announcement', 'label': '公告',
             'rows': n_announce,
             'size': _table_byte_size('announcement'),
             'cleanable': False},
            {'name': 'user', 'label': '管理员账户',
             'rows': n_users,
             'size': _table_byte_size('user'),
             'cleanable': False},
        ],
        'log_files': log_files,
        'log_total_size': log_total,
        'log_total_human': _format_size(log_total),
        'log_backup_count': sum(1 for f in log_files if not f['is_active']),
        'realtime_cache_count': rt_count,
    }


def preview_cleanup_gpu_hourly(older_than_days: int) -> dict:
    cutoff = datetime.now() - timedelta(days=older_than_days)
    cnt = GpuHourlyUsage.query.filter(GpuHourlyUsage.hour < cutoff).count()
    return {'rows': cnt, 'cutoff': cutoff.isoformat()}


def cleanup_gpu_hourly_older_than(older_than_days: int) -> int:
    cutoff = datetime.now() - timedelta(days=older_than_days)
    deleted = GpuHourlyUsage.query.filter(GpuHourlyUsage.hour < cutoff).delete()
    db.session.commit()
    logger.info(f"管理员清理 gpu_hourly_usage: 删除 {deleted} 行(< {cutoff.date()})")
    return deleted


def preview_cleanup_llm_reports(keep_latest_n: int) -> dict:
    total = LlmReport.query.count()
    return {'rows': max(0, total - keep_latest_n), 'total': total}


def cleanup_llm_reports_keep(keep_latest_n: int) -> int:
    keep_latest_n = max(0, int(keep_latest_n))
    ids_to_keep = [r.id for r in LlmReport.query
                   .order_by(LlmReport.generated_at.desc())
                   .limit(keep_latest_n).all()]
    if ids_to_keep:
        deleted = LlmReport.query.filter(~LlmReport.id.in_(ids_to_keep)) \
            .delete(synchronize_session=False)
    elif keep_latest_n == 0:
        deleted = LlmReport.query.delete()
    else:
        deleted = 0
    db.session.commit()
    logger.info(f"管理员清理 llm_report: 保留 {keep_latest_n} 条,删除 {deleted} 条")
    return deleted


def preview_cleanup_uptime(older_than_days: int) -> dict:
    from server import UptimeRecord
    cutoff_date = (datetime.now() - timedelta(days=older_than_days)).date()
    cnt = UptimeRecord.query.filter(UptimeRecord.date < cutoff_date).count()
    return {'rows': cnt, 'cutoff': cutoff_date.isoformat()}


def cleanup_uptime_older_than(older_than_days: int) -> int:
    from server import UptimeRecord
    cutoff_date = (datetime.now() - timedelta(days=older_than_days)).date()
    deleted = UptimeRecord.query.filter(UptimeRecord.date < cutoff_date).delete()
    db.session.commit()
    logger.info(f"管理员清理 uptime_record: 删除 {deleted} 行(< {cutoff_date})")
    return deleted


def cleanup_log_backups() -> dict:
    """Delete rotated server.log.1, .2, .3, ... but keep the active server.log."""
    deleted = []
    freed = 0
    for log_dir in ['/var/log/system-monitor',
                    os.path.dirname(os.path.abspath(__file__))]:
        if not os.path.isdir(log_dir):
            continue
        for name in os.listdir(log_dir):
            if name.startswith('server.log.'):
                full = os.path.join(log_dir, name)
                try:
                    sz = os.path.getsize(full)
                    os.remove(full)
                    deleted.append(name)
                    freed += sz
                except OSError as e:
                    logger.warning(f"删除日志备份失败 {full}: {e}")
        if deleted:
            break
    logger.info(f"管理员清理日志备份: 删除 {len(deleted)} 个文件,释放 {freed / 1024:.1f} KB")
    return {'deleted_count': len(deleted), 'bytes_freed': freed}


def vacuum_database() -> dict:
    db_uri = current_app.config.get('SQLALCHEMY_DATABASE_URI', '')
    db_path = db_uri.replace('sqlite:///', '') if db_uri.startswith('sqlite:///') else None
    if not db_path or not os.path.exists(db_path):
        return {'before': 0, 'after': 0, 'freed': 0}
    before = os.path.getsize(db_path)
    db.session.commit()
    db.session.execute(db.text('VACUUM'))
    db.session.commit()
    after = os.path.getsize(db_path)
    logger.info(f"管理员 VACUUM: {before} → {after} bytes ({(before - after) / 1024:.1f} KB freed)")
    return {'before': before, 'after': after, 'freed': max(0, before - after)}


@gpu_report_bp.route('/api/idle.json')
@login_required
def api_idle():
    return jsonify({'timestamp': datetime.now().isoformat(),
                    'idle_gpus': get_idle_gpus()})
