"""Phase 5: /gpu-report 路由和 API 测试。"""
import pytest
import json
from datetime import datetime, timedelta


def test_gpu_report_requires_login(client):
    resp = client.get('/gpu-report/')
    assert resp.status_code == 302
    assert '/login' in resp.headers.get('Location', '')


def test_gpu_report_accessible_when_logged_in(logged_in_client):
    resp = logged_in_client.get('/gpu-report/')
    assert resp.status_code == 200


def test_gpu_report_no_data_renders_ok(logged_in_client):
    resp = logged_in_client.get('/gpu-report/')
    assert resp.status_code == 200
    html = resp.data.decode()
    # Summary strip should appear even with no data
    assert 'GPU' in html


def test_api_heatmap_requires_login(client):
    resp = client.get('/gpu-report/api/heatmap.json')
    assert resp.status_code == 302


def test_api_heatmap_returns_json_structure(app, logged_in_client):
    from gpu_report import GpuHourlyUsage
    from server import db, Client

    with app.app_context():
        c = Client(id='cli-hm', hostname='srv', ip_address='10.0.0.1',
                   display_name='srv', platform='linux', display_order=0)
        db.session.add(c)
        db.session.commit()  # client must exist before FK reference
        hour = datetime.now().replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
        r = GpuHourlyUsage(client_id='cli-hm', gpu_index=0, hour=hour,
                            gpu_name='RTX', vram_pct_avg=60.0, ok_sample_count=60)
        db.session.add(r)
        db.session.commit()

    resp = logged_in_client.get('/gpu-report/api/heatmap.json?days=7')
    assert resp.status_code == 200
    data = resp.get_json()
    assert 'rows' in data
    assert data['hours'] == 168
    assert len(data['rows']) == 1
    assert len(data['rows'][0]['cells']) == 168


def test_api_idle_requires_login(client):
    resp = client.get('/gpu-report/api/idle.json')
    assert resp.status_code == 302


def test_api_idle_returns_json(logged_in_client):
    resp = logged_in_client.get('/gpu-report/api/idle.json')
    assert resp.status_code == 200
    data = resp.get_json()
    assert 'idle_gpus' in data
    assert 'timestamp' in data


def test_api_idle_excludes_errored_gpus(app, logged_in_client):
    from server import client_realtime_data, Client, db

    with app.app_context():
        c = Client(id='cli-idle-err', hostname='srv', ip_address='10.0.0.2',
                   display_name='srv', platform='linux', display_order=0)
        c.last_seen = datetime.now()
        db.session.add(c)
        db.session.commit()

    client_realtime_data['cli-idle-err'] = {
        'gpu': [
            {'index': 0, 'name': 'RTX', 'status': 'ok',
             'utilization': 2.0, 'memory_used': 100.0, 'memory_total': 24576.0},
            {'index': 1, 'name': 'RTX', 'status': 'error', 'error': '[N/A]'},
        ],
        'gpu_last_ok': {},
    }

    resp = logged_in_client.get('/gpu-report/api/idle.json')
    data = resp.get_json()
    gpu_indices = [g['gpu_index'] for g in data['idle_gpus']
                   if g['hostname'] == 'srv']
    assert 1 not in gpu_indices  # errored GPU should not appear
    assert 0 in gpu_indices      # ok idle GPU should appear
