"""设置页 side endpoints —— 从 server.py 拆出来,保持 endpoint 名不变。

/settings 主入口仍在 server.py(密码修改与会话耦合紧),这里收所有
保留策略 / LLM 配置 / 清理 / 导入导出动作。模块化拆分(非 Blueprint),
endpoint 名一行不变,模板的 url_for() 全部继续工作。
"""
import csv as _csv
import io as _io
import json
import os
import sqlite3
import time as _time
from datetime import datetime

from flask import (
    Response, flash, jsonify, redirect, request, send_file, session, url_for,
)

from server import app, db, logger
from auth import login_required


# 导出时不应包含的敏感键 — admin 想看 API key 应该直接读服务器文件,
# 不要走 HTTP 下载通道。
_EXPORT_REDACTED_KEYS = frozenset({'llm_api_key'})


# ─── 保留策略 ────────────────────────────────────────────────────────────────

@app.route('/settings/save_retention', methods=['POST'])
@login_required
def save_retention():
    from gpu_report import save_runtime_settings, SETTING_BOUNDS
    updates = {}
    errors = []

    field_map = [
        ('gpu_hourly_days', 'retention_days', 'GPU 小时数据保留'),
        ('llm_report_count', 'llm_report_retention', 'LLM 周报保留'),
        ('uptime_days', 'uptime_record_retention_days', '可用性记录保留'),
    ]
    for form_key, cfg_key, label in field_map:
        raw = request.form.get(form_key)
        if raw is None or raw == '':
            continue
        try:
            n = int(raw)
        except ValueError:
            errors.append(f'{label} 不是合法整数')
            continue
        lo, hi = SETTING_BOUNDS[cfg_key]
        if not (lo <= n <= hi):
            errors.append(f'{label} 必须在 {lo} ~ {hi} 之间')
            continue
        updates[cfg_key] = n

    if errors:
        for e in errors:
            flash(e, 'danger')
    elif updates:
        save_runtime_settings(updates, app=app)
        flash(f'已保存:{", ".join(f"{k}={v}" for k, v in updates.items())}', 'success')
    else:
        flash('没有更新任何设置', 'info')
    return redirect(url_for('settings'))


# ─── 清理动作 ────────────────────────────────────────────────────────────────

@app.route('/settings/cleanup_gpu_hourly', methods=['POST'])
@login_required
def admin_cleanup_gpu_hourly():
    from gpu_report import cleanup_gpu_hourly_older_than
    try:
        days = int(request.form.get('older_than_days', 7))
    except ValueError:
        flash('参数不是合法整数', 'danger')
        return redirect(url_for('settings'))
    if days < 1 or days > 3650:
        flash('天数必须在 1 ~ 3650 之间', 'danger')
        return redirect(url_for('settings'))
    deleted = cleanup_gpu_hourly_older_than(days)
    flash(f'清理完成:删除 {deleted} 行 GPU 小时数据(早于 {days} 天前)', 'success')
    return redirect(url_for('settings'))


@app.route('/settings/cleanup_llm_reports', methods=['POST'])
@login_required
def admin_cleanup_llm_reports():
    from gpu_report import cleanup_llm_reports_keep
    try:
        keep = int(request.form.get('keep_latest_n', 12))
    except ValueError:
        flash('参数不是合法整数', 'danger')
        return redirect(url_for('settings'))
    if keep < 0 or keep > 1000:
        flash('保留条数必须在 0 ~ 1000 之间', 'danger')
        return redirect(url_for('settings'))
    deleted = cleanup_llm_reports_keep(keep)
    flash(f'清理完成:保留最近 {keep} 条 LLM 周报,删除 {deleted} 条', 'success')
    return redirect(url_for('settings'))


@app.route('/settings/cleanup_uptime', methods=['POST'])
@login_required
def admin_cleanup_uptime():
    from gpu_report import cleanup_uptime_older_than
    try:
        days = int(request.form.get('older_than_days', 90))
    except ValueError:
        flash('参数不是合法整数', 'danger')
        return redirect(url_for('settings'))
    if days < 7 or days > 3650:
        flash('天数必须在 7 ~ 3650 之间', 'danger')
        return redirect(url_for('settings'))
    deleted = cleanup_uptime_older_than(days)
    flash(f'清理完成:删除 {deleted} 行可用性记录(早于 {days} 天前)', 'success')
    return redirect(url_for('settings'))


@app.route('/settings/cleanup_log_backups', methods=['POST'])
@login_required
def admin_cleanup_log_backups():
    from gpu_report import cleanup_log_backups
    res = cleanup_log_backups()
    flash(f'清理完成:删除 {res["deleted_count"]} 个轮转日志文件,释放 '
          f'{res["bytes_freed"] / 1024:.1f} KB', 'success')
    return redirect(url_for('settings'))


# ─── LLM 配置 ────────────────────────────────────────────────────────────────

@app.route('/settings/save_llm', methods=['POST'])
@login_required
def save_llm_settings():
    """保存 LLM 配置(provider / model / base_url / api_key / cron)。"""
    from gpu_report import save_runtime_settings
    updates = {}

    provider = request.form.get('llm_provider', '').strip()
    if provider in ('anthropic', 'openai'):
        updates['llm_provider'] = provider

    for field in ('llm_model', 'llm_base_url', 'llm_schedule_cron'):
        val = request.form.get(field, '').strip()
        if val:
            updates[field] = val

    # API key:仅在用户主动修改时才存(空提交表示"保持不变")
    api_key = request.form.get('llm_api_key', '').strip()
    if api_key:
        if api_key == '(env)':
            pass  # 占位符,用户没改,不更新
        else:
            updates['llm_api_key'] = api_key
    clear_key = request.form.get('clear_api_key')
    if clear_key:
        updates['llm_api_key'] = ''

    if updates:
        save_runtime_settings(updates, app=app)
        flash(f'LLM 配置已保存', 'success')
    else:
        flash('未检测到变化', 'info')
    return redirect(url_for('settings'))


@app.route('/settings/test_llm', methods=['POST'])
@login_required
def test_llm_connection():
    """测试 LLM API 连通性,返回 JSON。"""
    from gpu_report.llm_agent import _build_llm_client, _call_llm
    from gpu_report.config import _get_cfg

    cfg = _get_cfg()
    # 允许前端临时覆盖(测试前填写但未保存)
    for field in ('llm_provider', 'llm_model', 'llm_base_url', 'llm_api_key'):
        val = request.json.get(field, '').strip() if request.is_json else ''
        if val and val != '(env)':
            cfg = {**cfg, field: val}

    sdk_client, err = _build_llm_client(cfg)
    if sdk_client is None:
        return jsonify({'ok': False, 'error': err}), 200

    t0 = _time.time()
    try:
        content, in_tok, out_tok = _call_llm(
            sdk_client, cfg,
            [{"role": "user", "content": "Reply with exactly: OK"}],
            max_tokens=20,
        )
        latency_ms = int((_time.time() - t0) * 1000)
        return jsonify({
            'ok': True,
            'model': cfg.get('llm_model'),
            'response': content.strip()[:80],
            'latency_ms': latency_ms,
            'input_tokens': in_tok,
            'output_tokens': out_tok,
        })
    except Exception as e:
        latency_ms = int((_time.time() - t0) * 1000)
        return jsonify({'ok': False, 'error': str(e), 'latency_ms': latency_ms})


@app.route('/settings/llm_models')
@login_required
def list_llm_models():
    """返回可用模型列表。Anthropic 用内置清单,OpenAI 兼容端点调 /v1/models。"""
    from gpu_report.llm_agent import _build_llm_client
    from gpu_report.config import _get_cfg, ANTHROPIC_KNOWN_MODELS

    cfg = _get_cfg()
    provider = cfg.get('llm_provider', 'anthropic')

    if provider == 'anthropic':
        return jsonify({'ok': True, 'models': ANTHROPIC_KNOWN_MODELS,
                        'source': 'built-in list'})

    # OpenAI-compatible: try /v1/models
    sdk_client, err = _build_llm_client(cfg)
    if sdk_client is None:
        return jsonify({'ok': False, 'error': err})
    try:
        resp = sdk_client.models.list()
        models = sorted([m.id for m in resp.data])
        return jsonify({'ok': True, 'models': models, 'source': 'api'})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


# ─── DB 维护 ─────────────────────────────────────────────────────────────────

@app.route('/settings/vacuum_db', methods=['POST'])
@login_required
def admin_vacuum_db():
    from gpu_report import vacuum_database
    res = vacuum_database()
    flash(f'VACUUM 完成:{res["before"] / 1024:.1f} KB → '
          f'{res["after"] / 1024:.1f} KB(回收 {res["freed"] / 1024:.1f} KB)',
          'success')
    return redirect(url_for('settings'))


# ─── 导出 ────────────────────────────────────────────────────────────────────

@app.route('/settings/export/db')
@login_required
def export_db():
    """整库 SQLite 文件下载,可用于异地备份/迁移。"""
    db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
    if not db_uri.startswith('sqlite:///'):
        flash('当前 DB 不是 SQLite,无法直接下载', 'danger')
        return redirect(url_for('settings'))
    db_path = db_uri.replace('sqlite:///', '')
    if not os.path.exists(db_path) or db_path == ':memory:':
        flash('数据库文件不存在或为内存模式', 'danger')
        return redirect(url_for('settings'))

    # 在导出前 commit 任何 pending 状态,确保磁盘文件最新
    db.session.commit()
    filename = f'omni-status-monitor-{datetime.now().strftime("%Y%m%d-%H%M%S")}.db'
    logger.info(f"管理员 {session.get('username')} 导出整库 → {filename}")
    return send_file(db_path, as_attachment=True, download_name=filename,
                     mimetype='application/octet-stream')


@app.route('/settings/export/gpu_hourly.csv')
@login_required
def export_gpu_hourly_csv():
    """GpuHourlyUsage 全量 CSV 导出,适合 pandas / Excel 分析。

    113 GPU × 168 小时 ≈ 19k 行,内存里凑成一个字符串就够,不需要 stream。
    """
    from gpu_report import GpuHourlyUsage

    buf = _io.StringIO()
    buf.write('﻿')  # UTF-8 BOM 让 Excel 不乱码
    w = _csv.writer(buf)
    w.writerow(['client_id', 'gpu_index', 'hour', 'gpu_name',
                'vram_pct_avg', 'vram_pct_peak', 'util_pct_avg', 'util_pct_peak',
                'ok_sample_count', 'error_count'])
    rows = (GpuHourlyUsage.query
            .order_by(GpuHourlyUsage.client_id,
                      GpuHourlyUsage.gpu_index,
                      GpuHourlyUsage.hour)
            .all())
    for r in rows:
        w.writerow([r.client_id, r.gpu_index, r.hour.isoformat(),
                    r.gpu_name or '',
                    r.vram_pct_avg, r.vram_pct_peak,
                    r.util_pct_avg, r.util_pct_peak,
                    r.ok_sample_count, r.error_count])

    filename = f'gpu_hourly-{datetime.now().strftime("%Y%m%d-%H%M%S")}.csv'
    logger.info(f"管理员 {session.get('username')} 导出 {len(rows)} 行 GpuHourlyUsage")
    return Response(buf.getvalue(), mimetype='text/csv; charset=utf-8',
                    headers={'Content-Disposition':
                             f'attachment; filename="{filename}"'})


@app.route('/settings/export/llm_reports.json')
@login_required
def export_llm_reports():
    """所有 LlmReport 的 JSON 导出,可在被 cleanup 之前归档历史摘要。"""
    from gpu_report import LlmReport
    rows = LlmReport.query.order_by(LlmReport.generated_at.desc()).all()
    payload = [{
        'generated_at': r.generated_at.isoformat() if r.generated_at else None,
        'period_start': r.period_start.isoformat() if r.period_start else None,
        'period_end': r.period_end.isoformat() if r.period_end else None,
        'model': r.model, 'status': r.status, 'content': r.content,
        'input_tokens': r.input_tokens, 'output_tokens': r.output_tokens,
    } for r in rows]
    filename = f'llm_reports-{datetime.now().strftime("%Y%m%d-%H%M%S")}.json'
    body = json.dumps({'count': len(payload), 'reports': payload},
                      ensure_ascii=False, indent=2)
    logger.info(f"管理员 {session.get('username')} 导出 {len(payload)} 条 LLM 周报")
    return Response(body, mimetype='application/json; charset=utf-8',
                    headers={'Content-Disposition':
                             f'attachment; filename="{filename}"'})


@app.route('/settings/export/runtime_settings.json')
@login_required
def export_runtime_settings():
    """导出运行时配置。敏感字段(API key 等)从输出中剔除,
    避免通过浏览器下载或抓包泄露 — admin 想看 key 应该直接读服务器文件。"""
    from gpu_report import load_runtime_settings
    rs = {k: v for k, v in load_runtime_settings().items()
          if k not in _EXPORT_REDACTED_KEYS}
    body = json.dumps(rs, ensure_ascii=False, indent=2)
    return Response(body, mimetype='application/json; charset=utf-8',
                    headers={'Content-Disposition':
                             'attachment; filename="runtime_settings.json"'})


# ─── 导入 ────────────────────────────────────────────────────────────────────

@app.route('/settings/import/db', methods=['POST'])
@login_required
def import_db():
    """上传一个 SQLite 备份文件替换当前 DB。"""
    upload = request.files.get('db_file')
    if not upload or not upload.filename:
        flash('未选择要上传的文件', 'danger')
        return redirect(url_for('settings'))

    db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
    if not db_uri.startswith('sqlite:///'):
        flash('当前 DB 不是 SQLite,无法导入', 'danger')
        return redirect(url_for('settings'))
    db_path = db_uri.replace('sqlite:///', '')
    if db_path == ':memory:':
        flash('当前为内存模式,导入无意义', 'danger')
        return redirect(url_for('settings'))

    # Read first 16 bytes to verify SQLite magic
    head = upload.stream.read(16)
    if not head.startswith(b'SQLite format 3\x00'):
        flash('文件不是 SQLite 数据库(magic bytes 不匹配)', 'danger')
        return redirect(url_for('settings'))
    upload.stream.seek(0)

    backup_path = db_path + '.before-restore-' + datetime.now().strftime('%Y%m%d-%H%M%S')
    tmp_path = db_path + '.uploading'
    try:
        # 写入临时文件,完整后做原子替换
        with open(tmp_path, 'wb') as f:
            chunk_size = 1024 * 1024
            while True:
                chunk = upload.stream.read(chunk_size)
                if not chunk:
                    break
                f.write(chunk)

        # Sanity check: try to open uploaded file as SQLite and ensure required tables
        try:
            with sqlite3.connect(tmp_path) as conn:
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                names = {r[0] for r in cur.fetchall()}
        except sqlite3.DatabaseError as e:
            os.remove(tmp_path)
            flash(f'文件不是合法 SQLite 数据库:{e}', 'danger')
            return redirect(url_for('settings'))

        required = {'client', 'user'}
        if not required.issubset(names):
            os.remove(tmp_path)
            flash(f'数据库结构不匹配 omni-status(缺少表: {required - names})', 'danger')
            return redirect(url_for('settings'))

        # 关闭 SQLAlchemy 现有连接,以便能替换文件
        db.session.commit()
        db.engine.dispose()

        # 备份当前 DB,然后用上传的替换
        if os.path.exists(db_path):
            os.replace(db_path, backup_path)
        os.replace(tmp_path, db_path)
        # 触发 SQLAlchemy 在下次请求时重连
        db.engine.dispose()

        flash(f'数据库导入成功 · 旧库已备份为 {os.path.basename(backup_path)}', 'success')
        logger.info(f"管理员 {session.get('username')} 导入 DB,旧库备份 → {backup_path}")
    except Exception as e:
        # 失败时尝试回滚
        if os.path.exists(tmp_path):
            try: os.remove(tmp_path)
            except OSError: pass
        if os.path.exists(backup_path) and not os.path.exists(db_path):
            try: os.replace(backup_path, db_path)
            except OSError: pass
        flash(f'导入失败:{e}', 'danger')
        logger.error(f"DB 导入失败: {e}")

    return redirect(url_for('settings'))


@app.route('/settings/import/runtime_settings', methods=['POST'])
@login_required
def import_runtime_settings():
    """导入 runtime_settings.json,新值会经过相同的 bounds 校验。"""
    upload = request.files.get('settings_file')
    if not upload or not upload.filename:
        flash('未选择要上传的文件', 'danger')
        return redirect(url_for('settings'))

    try:
        data = json.loads(upload.stream.read().decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        flash(f'文件不是合法 JSON:{e}', 'danger')
        return redirect(url_for('settings'))
    if not isinstance(data, dict):
        flash('JSON 必须是对象 (key-value)', 'danger')
        return redirect(url_for('settings'))

    from gpu_report import save_runtime_settings, SETTING_BOUNDS
    valid = {}
    for k, v in data.items():
        if k in SETTING_BOUNDS:
            try:
                n = int(v)
            except (ValueError, TypeError):
                continue
            lo, hi = SETTING_BOUNDS[k]
            if lo <= n <= hi:
                valid[k] = n
    if not valid:
        flash('文件中没有可识别 / 合法的设置项', 'warning')
    else:
        save_runtime_settings(valid, app=app)
        flash(f'导入了 {len(valid)} 项设置:{", ".join(valid.keys())}', 'success')
    return redirect(url_for('settings'))
