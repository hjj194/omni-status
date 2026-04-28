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
    assert 'machines' in data
    assert data['days'] == 7
    assert len(data['day_labels']) == 7
    assert len(data['machines']) == 1
    machine = data['machines'][0]
    assert machine['hostname'] == 'srv'
    assert machine['gpu_count'] == 1
    assert len(machine['days']) == 7  # daily aggregated
    assert len(machine['gpus']) == 1
    assert len(machine['gpus'][0]['days']) == 7
    # Each daily cell carries a 24-hour sparkline
    assert len(machine['days'][0]['sparkline']) == 24


def test_heatmap_groups_multiple_gpus_under_one_machine(app, logged_in_client):
    """同机器多张卡应当被聚合到一个 machine 节点下,带 rollup_cells。"""
    from gpu_report import GpuHourlyUsage
    from server import db, Client

    with app.app_context():
        c = Client(id='multi-gpu', hostname='multi', ip_address='10.0.0.20',
                   display_name='multi', platform='linux', display_order=0)
        db.session.add(c)
        db.session.commit()

        hour = datetime.now().replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
        # 4 张卡同一小时:GPU 0 高占,GPU 1-3 空闲
        for gidx, vram in enumerate([85.0, 5.0, 8.0, 3.0]):
            db.session.add(GpuHourlyUsage(
                client_id='multi-gpu', gpu_index=gidx, hour=hour,
                gpu_name=f'RTX-{gidx}', vram_pct_avg=vram,
                util_pct_avg=vram - 5, ok_sample_count=60,
            ))
        db.session.commit()

    resp = logged_in_client.get('/gpu-report/api/heatmap.json?days=7')
    data = resp.get_json()
    machine = next(m for m in data['machines'] if m['client_id'] == 'multi-gpu')

    assert machine['gpu_count'] == 4
    assert len(machine['gpus']) == 4
    # Find the day containing the seeded hour and check rollup
    seeded_day = next((d for d in machine['days']
                        if d['vram_max'] is not None and d['vram_max'] >= 85.0), None)
    assert seeded_day is not None
    assert seeded_day['status'] == 'high'  # 85 ≥ heatmap_high_threshold (70)
    # Rollup max should reflect max(85, 5, 8, 3) = 85
    assert seeded_day['vram_max'] == 85.0


def test_heatmap_machines_sorted_by_display_order(app, logged_in_client):
    from gpu_report import GpuHourlyUsage
    from server import db, Client

    with app.app_context():
        for i, (cid, host, order) in enumerate([
            ('order-c', 'srv-c', 2),
            ('order-a', 'srv-a', 0),
            ('order-b', 'srv-b', 1),
        ]):
            db.session.add(Client(id=cid, hostname=host, ip_address=f'10.1.0.{i}',
                                   display_name=host, platform='linux',
                                   display_order=order))
        db.session.commit()
        hour = datetime.now().replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
        for cid in ('order-a', 'order-b', 'order-c'):
            db.session.add(GpuHourlyUsage(
                client_id=cid, gpu_index=0, hour=hour, gpu_name='X',
                vram_pct_avg=50.0, ok_sample_count=10,
            ))
        db.session.commit()

    data = logged_in_client.get('/gpu-report/api/heatmap.json?days=7').get_json()
    hostnames = [m['hostname'] for m in data['machines']
                  if m['client_id'].startswith('order-')]
    assert hostnames == ['srv-a', 'srv-b', 'srv-c']


def test_detail_page_requires_login(client):
    resp = client.get('/gpu-report/detail/some-cli')
    assert resp.status_code == 302


def test_detail_page_404_for_missing_client(logged_in_client):
    resp = logged_in_client.get('/gpu-report/detail/does-not-exist')
    assert resp.status_code == 404


def test_detail_page_renders_machine_view(app, logged_in_client):
    from gpu_report import GpuHourlyUsage
    from server import db, Client

    with app.app_context():
        c = Client(id='detail-cli', hostname='detail-host', ip_address='10.5.5.5',
                   display_name='detail-host', platform='linux', display_order=0)
        db.session.add(c)
        db.session.commit()
        hour = datetime.now().replace(minute=0, second=0, microsecond=0) - timedelta(hours=2)
        for gidx in range(2):
            db.session.add(GpuHourlyUsage(
                client_id='detail-cli', gpu_index=gidx, hour=hour,
                gpu_name=f'GPU{gidx}', vram_pct_avg=60.0,
                util_pct_avg=50.0, ok_sample_count=60,
            ))
        db.session.commit()

    resp = logged_in_client.get('/gpu-report/detail/detail-cli')
    assert resp.status_code == 200
    html = resp.data.decode()
    assert 'detail-host' in html
    assert 'VRAM 占用率小时趋势' in html
    # Machine view shows breakdown for multiple GPUs
    assert 'Per-GPU Breakdown' in html


def test_detail_page_renders_single_gpu_view(app, logged_in_client):
    from gpu_report import GpuHourlyUsage
    from server import db, Client

    with app.app_context():
        c = Client(id='single-cli', hostname='one-host', ip_address='10.5.5.6',
                   display_name='one-host', platform='linux', display_order=0)
        db.session.add(c)
        db.session.commit()
        hour = datetime.now().replace(minute=0, second=0, microsecond=0) - timedelta(hours=2)
        db.session.add(GpuHourlyUsage(
            client_id='single-cli', gpu_index=3, hour=hour,
            gpu_name='RTX 4090', vram_pct_avg=80.0,
            util_pct_avg=70.0, ok_sample_count=60,
        ))
        db.session.commit()

    resp = logged_in_client.get('/gpu-report/detail/single-cli/3')
    assert resp.status_code == 200
    html = resp.data.decode()
    assert 'GPU 3' in html
    # Single-GPU view should not show the per-GPU breakdown panel
    assert 'Per-GPU Breakdown' not in html


def test_api_detail_returns_series(app, logged_in_client):
    from gpu_report import GpuHourlyUsage
    from server import db, Client

    with app.app_context():
        c = Client(id='api-cli', hostname='api-host', ip_address='10.5.5.7',
                   display_name='api-host', platform='linux', display_order=0)
        db.session.add(c)
        db.session.commit()
        hour = datetime.now().replace(minute=0, second=0, microsecond=0) - timedelta(hours=2)
        db.session.add(GpuHourlyUsage(
            client_id='api-cli', gpu_index=0, hour=hour,
            gpu_name='RTX', vram_pct_avg=70.0, util_pct_avg=60.0,
            ok_sample_count=60,
        ))
        db.session.commit()

    resp = logged_in_client.get('/gpu-report/api/detail/api-cli.json')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['client_id'] == 'api-cli'
    assert len(data['series_vram']) == 168
    assert data['stats']['vram_peak'] == 70.0
    assert len(data['gpus']) == 1


def test_api_detail_404_for_missing_client(logged_in_client):
    resp = logged_in_client.get('/gpu-report/api/detail/nope.json')
    assert resp.status_code == 404


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
