"""Phase 3: Dashboard 坏卡渲染测试。"""
import pytest
import json
from datetime import datetime


def post_report(client, payload):
    return client.post('/report', data=json.dumps(payload),
                       content_type='application/json')


def base_payload(client_id, gpus):
    return {
        'client_id': client_id,
        'timestamp': datetime.now().isoformat(),
        'hostname': 'lab-srv',
        'ip_address': '10.0.0.1',
        'platform': 'Linux',
        'cpu': {'count': 8, 'usage_percent': 15.0},
        'memory': {'total': 16 * 1024 ** 3, 'used': 4 * 1024 ** 3, 'percent': 25.0},
        'disks': [{'device': '/dev/sda', 'mountpoint': '/', 'total': 100 * 1024 ** 3,
                   'used': 50 * 1024 ** 3, 'percent': 50.0}],
        'gpu': gpus,
        'uptime_seconds': 7200,
    }


def test_dashboard_renders_ok_gpus_normally(client):
    gpus = [{'index': 0, 'name': 'RTX 3090', 'status': 'ok',
              'utilization': 70.0, 'memory_used': 18000.0, 'memory_total': 24576.0}]
    post_report(client, base_payload('cli-ok', gpus))
    resp = client.get('/')
    html = resp.data.decode()
    assert 'RTX 3090' in html
    assert resp.status_code == 200


def test_dashboard_renders_error_gpu_with_red_box(client):
    gpus = [
        {'index': 0, 'name': 'RTX 3090', 'status': 'ok',
         'utilization': 70.0, 'memory_used': 18000.0, 'memory_total': 24576.0},
        {'index': 1, 'name': 'RTX 3090', 'status': 'error', 'error': '[N/A]'},
    ]
    post_report(client, base_payload('cli-err', gpus))
    resp = client.get('/')
    html = resp.data.decode()
    assert '硬件' in html or '驱动' in html or '异常' in html
    assert resp.status_code == 200


def test_dashboard_machine_online_when_gpu_errored(client):
    gpus = [{'index': 0, 'name': 'RTX 3090', 'status': 'error', 'error': '[N/A]'}]
    post_report(client, base_payload('cli-online-err', gpus))
    resp = client.get('/')
    html = resp.data.decode()
    # status-dot online should appear for this client
    assert 'online' in html
    assert resp.status_code == 200


def test_dashboard_survives_all_errored_gpus(client):
    """全部 GPU 是 error 时不崩溃。"""
    gpus = [
        {'index': 0, 'name': 'RTX', 'status': 'error', 'error': 'ERR'},
        {'index': 1, 'name': 'RTX', 'status': 'error', 'error': 'ERR'},
    ]
    post_report(client, base_payload('cli-all-err', gpus))
    resp = client.get('/')
    assert resp.status_code == 200


def test_dashboard_backward_compat_no_status_field(client):
    """旧客户端 gpu dict 没有 status 字段也能正常渲染。"""
    gpus = [{'index': 0, 'name': 'RTX 3090',
              'utilization': 55.0, 'memory_used': 12000.0, 'memory_total': 24576.0}]
    post_report(client, base_payload('cli-compat', gpus))
    resp = client.get('/')
    assert resp.status_code == 200
    html = resp.data.decode()
    assert 'RTX 3090' in html


def test_error_message_in_gpu_section_is_escaped(client):
    """error 原文含 HTML 特殊字符时不 XSS。"""
    gpus = [{'index': 0, 'name': 'GPU', 'status': 'error',
              'error': '<script>alert(1)</script>'}]
    post_report(client, base_payload('cli-xss', gpus))
    resp = client.get('/')
    html = resp.data.decode()
    assert '<script>alert(1)</script>' not in html
