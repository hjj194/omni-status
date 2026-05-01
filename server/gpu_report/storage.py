"""管理员 /settings 页面的存储统计 + 选择性清理 + VACUUM。"""
import logging
import os
from datetime import datetime, timedelta

from flask import current_app

from server import db, Client, client_realtime_data

from .models import GpuHourlyUsage, LlmReport

logger = logging.getLogger('system_monitor_server')


def _format_size(num_bytes: int) -> str:
    """1234 → '1.2 KB',1234567 → '1.2 MB' 等。"""
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
    """通过 SQLite dbstat 虚表估算单表占用(数据 + 索引)。"""
    try:
        result = db.session.execute(db.text(
            "SELECT SUM(pgsize) FROM dbstat WHERE name = :n OR name LIKE :idx_pat"
        ), {'n': table_name, 'idx_pat': f'sqlite_autoindex_{table_name}_%'})
        v = result.scalar()
        if v is not None:
            return int(v)
    except Exception:
        pass
    return -1


def get_storage_stats():
    """快照:磁盘 + DB + 各表行数 + 日志文件清单 + 内存缓存。"""
    db_uri = current_app.config.get('SQLALCHEMY_DATABASE_URI', '')
    db_path = db_uri.replace('sqlite:///', '') if db_uri.startswith('sqlite:///') else None
    db_size = os.path.getsize(db_path) if db_path and os.path.exists(db_path) else None

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

    log_files = []
    log_total = 0
    for log_dir in ['/var/log/system-monitor',
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))]:
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


# ─── 预览(给前端 modal 显示"将删除多少行")──────────────────────

def preview_cleanup_gpu_hourly(older_than_days: int) -> dict:
    cutoff = datetime.now() - timedelta(days=older_than_days)
    cnt = GpuHourlyUsage.query.filter(GpuHourlyUsage.hour < cutoff).count()
    return {'rows': cnt, 'cutoff': cutoff.isoformat()}


def preview_cleanup_llm_reports(keep_latest_n: int) -> dict:
    total = LlmReport.query.count()
    return {'rows': max(0, total - keep_latest_n), 'total': total}


def preview_cleanup_uptime(older_than_days: int) -> dict:
    from server import UptimeRecord
    cutoff_date = (datetime.now() - timedelta(days=older_than_days)).date()
    cnt = UptimeRecord.query.filter(UptimeRecord.date < cutoff_date).count()
    return {'rows': cnt, 'cutoff': cutoff_date.isoformat()}


# ─── 实际删除 ────────────────────────────────────────────────────

def cleanup_gpu_hourly_older_than(older_than_days: int) -> int:
    cutoff = datetime.now() - timedelta(days=older_than_days)
    deleted = GpuHourlyUsage.query.filter(GpuHourlyUsage.hour < cutoff).delete()
    db.session.commit()
    logger.info(f"管理员清理 gpu_hourly_usage: 删除 {deleted} 行(< {cutoff.date()})")
    return deleted


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


def cleanup_uptime_older_than(older_than_days: int) -> int:
    from server import UptimeRecord
    cutoff_date = (datetime.now() - timedelta(days=older_than_days)).date()
    deleted = UptimeRecord.query.filter(UptimeRecord.date < cutoff_date).delete()
    db.session.commit()
    logger.info(f"管理员清理 uptime_record: 删除 {deleted} 行(< {cutoff_date})")
    return deleted


def cleanup_log_backups() -> dict:
    """删除 server.log.1, .2, .3, ...,但保留正在用的 server.log。"""
    deleted = []
    freed = 0
    for log_dir in ['/var/log/system-monitor',
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))]:
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
    logger.info(f"管理员 VACUUM: {before} → {after} bytes "
                f"({(before - after) / 1024:.1f} KB freed)")
    return {'before': before, 'after': after, 'freed': max(0, before - after)}
