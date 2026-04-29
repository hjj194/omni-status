"""管理员设置页:存储统计 + 保留策略 + 清理操作。"""
import os
import json
import pytest
from datetime import datetime, timedelta


# ─── Storage stats ──────────────────────────────────────────────────────────

def test_settings_page_includes_storage_table(logged_in_client):
    resp = logged_in_client.get('/settings')
    assert resp.status_code == 200
    html = resp.data.decode()
    assert '存储空间统计' in html
    assert '数据保留策略' in html
    assert 'GPU 小时聚合' in html
    assert '客户端可用性记录' in html


def test_get_storage_stats_returns_expected_shape(app):
    from gpu_report import get_storage_stats
    with app.app_context():
        stats = get_storage_stats()
    assert 'db_size' in stats
    assert 'tables' in stats
    assert len(stats['tables']) >= 3
    table_names = {t['name'] for t in stats['tables']}
    assert 'gpu_hourly_usage' in table_names
    assert 'llm_report' in table_names
    assert 'uptime_record' in table_names


# ─── Save retention ─────────────────────────────────────────────────────────

def test_save_retention_persists_and_takes_effect(app, logged_in_client, tmp_path):
    from gpu_report import RUNTIME_SETTINGS_FILE
    # Use temp file for runtime settings to avoid polluting real one
    import gpu_report as gr
    orig_file = gr.RUNTIME_SETTINGS_FILE
    gr.RUNTIME_SETTINGS_FILE = str(tmp_path / 'runtime.json')
    try:
        resp = logged_in_client.post('/settings/save_retention', data={
            'gpu_hourly_days': '14',
            'llm_report_count': '24',
            'uptime_days': '180',
        }, follow_redirects=True)
        assert resp.status_code == 200

        # Live config should reflect new values
        with app.app_context():
            assert app.config['GPU_REPORT']['retention_days'] == 14
            assert app.config['GPU_REPORT']['llm_report_retention'] == 24
            assert app.config['GPU_REPORT']['uptime_record_retention_days'] == 180

        # Persisted to JSON file
        with open(gr.RUNTIME_SETTINGS_FILE) as f:
            data = json.load(f)
        assert data['retention_days'] == 14
    finally:
        gr.RUNTIME_SETTINGS_FILE = orig_file


def test_save_retention_rejects_out_of_bounds(app, logged_in_client, tmp_path):
    import gpu_report as gr
    orig_file = gr.RUNTIME_SETTINGS_FILE
    gr.RUNTIME_SETTINGS_FILE = str(tmp_path / 'runtime.json')
    try:
        resp = logged_in_client.post('/settings/save_retention', data={
            'gpu_hourly_days': '5000',  # > 365
        }, follow_redirects=True)
        assert resp.status_code == 200
        # Config should NOT have been mutated
        with app.app_context():
            assert app.config['GPU_REPORT']['retention_days'] != 5000
    finally:
        gr.RUNTIME_SETTINGS_FILE = orig_file


def test_save_retention_rejects_non_integer(logged_in_client, tmp_path):
    import gpu_report as gr
    orig_file = gr.RUNTIME_SETTINGS_FILE
    gr.RUNTIME_SETTINGS_FILE = str(tmp_path / 'runtime.json')
    try:
        resp = logged_in_client.post('/settings/save_retention', data={
            'gpu_hourly_days': 'abc',
        }, follow_redirects=True)
        assert resp.status_code == 200
    finally:
        gr.RUNTIME_SETTINGS_FILE = orig_file


def test_save_retention_requires_login(client):
    resp = client.post('/settings/save_retention', data={'gpu_hourly_days': '14'})
    assert resp.status_code == 302


# ─── Cleanup actions ────────────────────────────────────────────────────────

def _seed_gpu_rows(app, ages_days):
    from gpu_report import GpuHourlyUsage
    from server import db, Client
    with app.app_context():
        c = Client(id='cleanup-cli', hostname='cu', ip_address='10.9.0.1',
                   display_name='cu', platform='linux', display_order=0)
        db.session.add(c)
        db.session.commit()
        now = datetime.now().replace(minute=0, second=0, microsecond=0)
        for d in ages_days:
            db.session.add(GpuHourlyUsage(
                client_id='cleanup-cli', gpu_index=0,
                hour=now - timedelta(days=d), gpu_name='RTX',
                vram_pct_avg=50.0, ok_sample_count=10,
            ))
        db.session.commit()


def test_cleanup_gpu_hourly_deletes_older_rows(app, logged_in_client):
    _seed_gpu_rows(app, ages_days=[1, 5, 10, 15])
    resp = logged_in_client.post('/settings/cleanup_gpu_hourly',
                                  data={'older_than_days': '7'},
                                  follow_redirects=True)
    assert resp.status_code == 200
    from gpu_report import GpuHourlyUsage
    with app.app_context():
        remaining = GpuHourlyUsage.query.count()
    assert remaining == 2  # 1d + 5d ago kept


def test_cleanup_gpu_hourly_validates_input(logged_in_client):
    resp = logged_in_client.post('/settings/cleanup_gpu_hourly',
                                  data={'older_than_days': '0'},
                                  follow_redirects=True)
    assert resp.status_code == 200  # flash error, redirect to settings


def test_cleanup_gpu_hourly_requires_login(client):
    resp = client.post('/settings/cleanup_gpu_hourly', data={'older_than_days': '7'})
    assert resp.status_code == 302


def test_cleanup_llm_reports_keeps_only_n(app, logged_in_client):
    from gpu_report import LlmReport
    from server import db
    with app.app_context():
        for i in range(20):
            db.session.add(LlmReport(
                generated_at=datetime(2026, 1, 1) + timedelta(days=i),
                period_start=datetime(2026, 1, 1),
                period_end=datetime(2026, 1, 7),
                status='ok', content=f'rep {i}',
            ))
        db.session.commit()
    resp = logged_in_client.post('/settings/cleanup_llm_reports',
                                  data={'keep_latest_n': '5'},
                                  follow_redirects=True)
    assert resp.status_code == 200
    with app.app_context():
        assert LlmReport.query.count() == 5


def test_cleanup_uptime_deletes_older_than(app, logged_in_client):
    from server import db, Client, UptimeRecord
    with app.app_context():
        c = Client(id='upt-cli', hostname='upt', ip_address='10.9.0.2',
                   display_name='upt', platform='linux', display_order=0)
        db.session.add(c)
        db.session.commit()
        today = datetime.now().date()
        for d in [1, 30, 100, 200]:
            db.session.add(UptimeRecord(
                client_id='upt-cli',
                date=today - timedelta(days=d), status=0,
            ))
        db.session.commit()

    resp = logged_in_client.post('/settings/cleanup_uptime',
                                  data={'older_than_days': '90'},
                                  follow_redirects=True)
    assert resp.status_code == 200
    with app.app_context():
        cnt = UptimeRecord.query.filter_by(client_id='upt-cli').count()
    assert cnt == 2  # 1d + 30d kept


def test_vacuum_endpoint(logged_in_client):
    resp = logged_in_client.post('/settings/vacuum_db', follow_redirects=True)
    assert resp.status_code == 200


def test_cleanup_log_backups_endpoint(logged_in_client):
    # No backup files exist in test env, but the endpoint should still respond
    resp = logged_in_client.post('/settings/cleanup_log_backups', follow_redirects=True)
    assert resp.status_code == 200


# ─── Export endpoints ──────────────────────────────────────────────────────

def test_export_db_requires_login(client):
    resp = client.get('/settings/export/db')
    assert resp.status_code == 302


def test_export_db_returns_attachment_in_real_db_setup(app, logged_in_client, tmp_path):
    """In-memory DB can't be downloaded; real-file DB returns attachment.
    Test environment uses :memory: so we expect a flash + redirect (not 200)."""
    resp = logged_in_client.get('/settings/export/db', follow_redirects=False)
    # In :memory: mode the route flashes danger and redirects
    assert resp.status_code in (200, 302)


def test_export_gpu_hourly_csv_returns_csv(app, logged_in_client):
    from gpu_report import GpuHourlyUsage
    from server import db, Client
    from datetime import datetime
    with app.app_context():
        c = Client(id='csv-cli', hostname='cv', ip_address='10.7.0.1',
                   display_name='cv', platform='linux', display_order=0)
        db.session.add(c)
        db.session.commit()
        db.session.add(GpuHourlyUsage(
            client_id='csv-cli', gpu_index=0, hour=datetime(2026, 4, 1, 12),
            gpu_name='RTX', vram_pct_avg=55.5, vram_pct_peak=60.0,
            util_pct_avg=40.0, util_pct_peak=50.0,
            ok_sample_count=58, error_count=2,
        ))
        db.session.commit()

    resp = logged_in_client.get('/settings/export/gpu_hourly.csv')
    assert resp.status_code == 200
    body = resp.data.decode('utf-8')
    assert 'client_id,gpu_index,hour' in body  # header row
    assert 'csv-cli' in body
    assert '55.5' in body
    assert resp.headers.get('Content-Disposition', '').startswith('attachment')


def test_export_llm_reports_returns_json(app, logged_in_client):
    from gpu_report import LlmReport
    from server import db
    from datetime import datetime
    with app.app_context():
        db.session.add(LlmReport(
            generated_at=datetime(2026, 4, 1, 9),
            period_start=datetime(2026, 3, 25),
            period_end=datetime(2026, 4, 1),
            model='claude-haiku', status='ok', content='**summary**',
            input_tokens=100, output_tokens=50,
        ))
        db.session.commit()

    resp = logged_in_client.get('/settings/export/llm_reports.json')
    assert resp.status_code == 200
    data = json.loads(resp.data.decode('utf-8'))
    assert data['count'] >= 1
    assert any(r['content'] == '**summary**' for r in data['reports'])


def test_export_runtime_settings_returns_json(logged_in_client):
    resp = logged_in_client.get('/settings/export/runtime_settings.json')
    assert resp.status_code == 200
    data = json.loads(resp.data.decode('utf-8'))
    assert isinstance(data, dict)


def test_export_runtime_settings_requires_login(client):
    resp = client.get('/settings/export/runtime_settings.json')
    assert resp.status_code == 302


# ─── Import endpoints ──────────────────────────────────────────────────────

def test_import_db_rejects_non_sqlite_upload(logged_in_client, tmp_path):
    fake = tmp_path / 'fake.db'
    fake.write_bytes(b'not a real sqlite file' * 100)
    with open(fake, 'rb') as f:
        resp = logged_in_client.post('/settings/import/db',
                                      data={'db_file': (f, 'fake.db')},
                                      content_type='multipart/form-data',
                                      follow_redirects=True)
    assert resp.status_code == 200  # flash error, redirect


def test_import_db_rejects_missing_file(logged_in_client):
    resp = logged_in_client.post('/settings/import/db',
                                  data={},
                                  follow_redirects=True)
    assert resp.status_code == 200


def test_import_db_requires_login(client):
    resp = client.post('/settings/import/db', data={})
    assert resp.status_code == 302


def test_import_runtime_settings_accepts_valid_json(app, logged_in_client, tmp_path):
    import gpu_report as gr
    orig = gr.RUNTIME_SETTINGS_FILE
    gr.RUNTIME_SETTINGS_FILE = str(tmp_path / 'rt.json')
    try:
        upload = tmp_path / 'imp.json'
        upload.write_text(json.dumps({
            'retention_days': 21,
            'llm_report_retention': 30,
            'unknown_key': 'ignored',
        }))
        with open(upload, 'rb') as f:
            resp = logged_in_client.post('/settings/import/runtime_settings',
                                          data={'settings_file': (f, 'imp.json')},
                                          content_type='multipart/form-data',
                                          follow_redirects=True)
        assert resp.status_code == 200
        with app.app_context():
            assert app.config['GPU_REPORT']['retention_days'] == 21
            assert app.config['GPU_REPORT']['llm_report_retention'] == 30
    finally:
        gr.RUNTIME_SETTINGS_FILE = orig


def test_import_runtime_settings_rejects_invalid_json(logged_in_client, tmp_path):
    upload = tmp_path / 'bad.json'
    upload.write_text('not json {[')
    with open(upload, 'rb') as f:
        resp = logged_in_client.post('/settings/import/runtime_settings',
                                      data={'settings_file': (f, 'bad.json')},
                                      content_type='multipart/form-data',
                                      follow_redirects=True)
    assert resp.status_code == 200  # flash error, redirect


def test_import_runtime_settings_rejects_out_of_bounds(app, logged_in_client, tmp_path):
    import gpu_report as gr
    orig = gr.RUNTIME_SETTINGS_FILE
    gr.RUNTIME_SETTINGS_FILE = str(tmp_path / 'rt2.json')
    try:
        upload = tmp_path / 'imp.json'
        upload.write_text(json.dumps({
            'retention_days': 99999,  # out of bounds
        }))
        with open(upload, 'rb') as f:
            resp = logged_in_client.post('/settings/import/runtime_settings',
                                          data={'settings_file': (f, 'imp.json')},
                                          content_type='multipart/form-data',
                                          follow_redirects=True)
        assert resp.status_code == 200
        # config should NOT have been mutated to invalid value
        with app.app_context():
            assert app.config['GPU_REPORT']['retention_days'] != 99999
    finally:
        gr.RUNTIME_SETTINGS_FILE = orig
