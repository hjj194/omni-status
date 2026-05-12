"""APScheduler 配置 + 周期清理任务。

- ``cleanup_hourly``:每小时 :05 删除超过 retention_days 的 GpuHourlyUsage,
  顺带按 uptime_record_retention_days 清理 UptimeRecord。
- ``cleanup_llm_reports``:每周日 03:00 保留最近 N 条。
- ``init_scheduler``:周一 09:00 触发 LLM 周报生成,守住 reloader 重复启动。
"""
import logging
from datetime import datetime, timedelta

from server import db

from .config import _get_cfg
from .models import GpuHourlyUsage, GpuUserHourlyUsage, LlmReport

logger = logging.getLogger('system_monitor_server')

_scheduler = None


def cleanup_hourly():
    cfg = _get_cfg()
    cutoff = datetime.now() - timedelta(days=cfg['retention_days'])
    deleted = GpuHourlyUsage.query.filter(GpuHourlyUsage.hour < cutoff).delete()
    u_deleted = GpuUserHourlyUsage.query.filter(GpuUserHourlyUsage.hour < cutoff).delete()
    db.session.commit()
    logger.info(f"GPU 小时数据清理: 删除 {deleted} 行(整机) + {u_deleted} 行(按用户),早于 {cutoff.date()}")

    # 同时按配置清理 UptimeRecord 防止无限累积。
    # 独立 try 块,失败时显式 rollback,避免把残留事务带到 session 里影响下个 job。
    # 用 logger.error + exc_info 而非 warning,这是真问题(表无限增长)不是噪音。
    try:
        from server import UptimeRecord
        uptime_cutoff = (datetime.now() -
                         timedelta(days=cfg.get('uptime_record_retention_days', 90))).date()
        ur_deleted = UptimeRecord.query.filter(UptimeRecord.date < uptime_cutoff).delete()
        if ur_deleted > 0:
            db.session.commit()
            logger.info(f"UptimeRecord 清理: 删除 {ur_deleted} 行(早于 {uptime_cutoff})")
    except Exception as e:
        try:
            db.session.rollback()
        except Exception as rb_err:
            logger.error(f"UptimeRecord 清理 rollback 失败: {rb_err}")
        logger.error(f"UptimeRecord 清理失败: {e}", exc_info=True)


def cleanup_llm_reports():
    cfg = _get_cfg()
    keep = max(1, int(cfg.get('llm_report_retention', 12)))  # 防御:绝不全删
    ids_to_keep = [r.id for r in LlmReport.query
                   .order_by(LlmReport.generated_at.desc())
                   .limit(keep).all()]
    if ids_to_keep:
        deleted = (LlmReport.query
                   .filter(~LlmReport.id.in_(ids_to_keep))
                   .delete(synchronize_session=False))
    else:
        deleted = 0  # 空表,什么都不做
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

    # 延迟 import 避免循环
    from .llm_agent import generate_llm_summary

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
