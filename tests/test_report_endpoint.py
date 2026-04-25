"""Phase 3: /report 端点集成测试。"""
import pytest
import json
from datetime import datetime
from unittest.mock import patch


def base_payload(client_id='cli-ep-001', gpus=None):
    return {
        'client_id': client_id,
        'timestamp': datetime.now().isoformat(),
        'hostname': 'lab-srv',
        'ip_address': '192.168.1.1',
        'platform': 'Linux',
        'cpu': {'count': 8, 'usage_percent': 20.0},
        'memory': {'total': 8 * 1024 ** 3, 'used': 2 * 1024 ** 3, 'percent': 25.0},
        'disks': [{'device': '/dev/sda', 'mountpoint': '/', 'total': 100 * 1024 ** 3,
                   'used': 50 * 1024 ** 3, 'percent': 50.0}],
        'gpu': gpus if gpus is not None else [],
        'uptime_seconds': 3600,
    }


def post_report(client, payload):
    return client.post('/report', data=json.dumps(payload),
                       content_type='application/json')


def test_report_endpoint_returns_200(client):
    resp = post_report(client, base_payload())
    assert resp.status_code == 200
    assert resp.get_json()['status'] == 'success'


def test_report_endpoint_ingests_hourly_sample(app, client):
    gpus = [{'index': 0, 'name': 'RTX 3090', 'status': 'ok',
              'utilization': 70.0, 'memory_used': 18000.0, 'memory_total': 24576.0}]
    post_report(client, base_payload(gpus=gpus))

    from gpu_report import GpuHourlyUsage
    with app.app_context():
        rows = GpuHourlyUsage.query.all()
    assert len(rows) == 1
    assert rows[0].ok_sample_count == 1
    assert rows[0].gpu_name == 'RTX 3090'


def test_report_endpoint_tolerates_ingest_failure(app, client):
    """ingest 抛异常时,dashboard 路径仍返回 200。"""
    gpus = [{'index': 0, 'name': 'RTX', 'status': 'ok',
              'utilization': 50.0, 'memory_used': 8000.0, 'memory_total': 24576.0}]
    payload = base_payload(gpus=gpus)
    with patch('gpu_report.ingest_hourly_sample', side_effect=RuntimeError('ingest boom')):
        resp = post_report(client, payload)
    assert resp.status_code == 200

    from server import client_realtime_data
    assert payload['client_id'] in client_realtime_data


def test_report_stores_gpu_last_ok_for_ok_gpus(app, client):
    gpus = [{'index': 0, 'name': 'RTX', 'status': 'ok',
              'utilization': 50.0, 'memory_used': 8000.0, 'memory_total': 24576.0}]
    post_report(client, base_payload(client_id='cli-last-ok', gpus=gpus))

    from server import client_realtime_data
    assert 0 in client_realtime_data.get('cli-last-ok', {}).get('gpu_last_ok', {})


def test_report_does_not_store_gpu_last_ok_for_error_gpus(app, client):
    gpus = [{'index': 0, 'name': 'RTX', 'status': 'error', 'error': '[N/A]'}]
    post_report(client, base_payload(client_id='cli-err-ok', gpus=gpus))

    from server import client_realtime_data
    last_ok = client_realtime_data.get('cli-err-ok', {}).get('gpu_last_ok', {})
    assert 0 not in last_ok


def test_report_preserves_previous_gpu_last_ok(app, client):
    """第二次上报 GPU 0 变 error 时,gpu_last_ok[0] 保留第一次的时间。"""
    ok_gpu = [{'index': 0, 'name': 'RTX', 'status': 'ok',
                'utilization': 50.0, 'memory_used': 8000.0, 'memory_total': 24576.0}]
    err_gpu = [{'index': 0, 'name': 'RTX', 'status': 'error', 'error': '[N/A]'}]

    post_report(client, base_payload(client_id='cli-preserve', gpus=ok_gpu))
    from server import client_realtime_data
    first_ts = client_realtime_data['cli-preserve']['gpu_last_ok'][0]

    post_report(client, base_payload(client_id='cli-preserve', gpus=err_gpu))
    preserved_ts = client_realtime_data['cli-preserve']['gpu_last_ok'].get(0)

    assert preserved_ts == first_ts
