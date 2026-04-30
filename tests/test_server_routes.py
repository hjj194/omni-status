"""覆盖 server.py 中未被其他测试模块覆盖的路由。"""
import json
import pytest
from datetime import datetime


def make_gpu(index=0, util=50.0, mem_used=10000.0, mem_total=24576.0):
    return {'index': index, 'name': 'RTX', 'status': 'ok',
            'utilization': util, 'memory_used': mem_used, 'memory_total': mem_total}


def report(client, client_id='srv-rt', gpus=None):
    payload = {
        'client_id': client_id,
        'timestamp': datetime.now().isoformat(),
        'hostname': 'test-srv',
        'ip_address': '10.0.0.99',
        'platform': 'Linux',
        'cpu': {'count': 4, 'usage_percent': 30.0},
        'memory': {'total': 8 * 1024 ** 3, 'used': 2 * 1024 ** 3, 'percent': 25.0},
        'disks': [{'device': '/dev/sda', 'mountpoint': '/', 'total': 100 * 1024 ** 3,
                   'used': 40 * 1024 ** 3, 'percent': 40.0}],
        'gpu': gpus or [],
        'uptime_seconds': 1000,
    }
    return client.post('/report', data=json.dumps(payload),
                       content_type='application/json')


def test_login_success_redirects_to_dashboard(app, client):
    """正常登录(密码已改)应跳到 dashboard。"""
    from server import User, db
    with app.app_context():
        admin = User.query.filter_by(username='admin').first()
        admin.must_change_password = False
        db.session.commit()
    resp = client.post('/login',
                       data={'username': 'admin', 'password': 'admin'},
                       follow_redirects=True)
    assert resp.status_code == 200
    assert 'Omni-Server-Status' in resp.data.decode('utf-8')


def test_login_failure_shows_error(client):
    resp = client.post('/login',
                       data={'username': 'admin', 'password': 'wrong'})
    assert resp.status_code == 200
    assert '错误' in resp.data.decode('utf-8') or 'error' in resp.data.decode('utf-8').lower()


def test_logout_redirects_to_dashboard(logged_in_client):
    resp = logged_in_client.get('/logout', follow_redirects=True)
    assert resp.status_code == 200


def test_dashboard_shows_reported_client(client):
    report(client, 'dash-client', [make_gpu()])
    resp = client.get('/')
    assert resp.status_code == 200
    assert 'test-srv' in resp.data.decode('utf-8')


def test_dashboard_offline_client_shown(client):
    report(client, 'dash-offline')
    resp = client.get('/')
    assert resp.status_code == 200


def test_edit_client_requires_login(client):
    report(client, 'edit-client')
    resp = client.get('/edit_client/edit-client')
    assert resp.status_code == 302
    assert '/login' in resp.headers.get('Location', '')


def test_edit_client_post(app, logged_in_client):
    report(logged_in_client, 'edit-cli-2')
    resp = logged_in_client.post('/edit_client/edit-cli-2',
                                 data={'display_name': 'My Server',
                                       'ip_address': '10.0.0.1',
                                       'physical_address': 'Lab A',
                                       'notes': 'Test note'},
                                 follow_redirects=True)
    assert resp.status_code == 200
    from server import Client, db
    with app.app_context():
        c = db.session.get(Client, 'edit-cli-2')
        assert c.display_name == 'My Server'


def test_delete_client_requires_login(client):
    report(client, 'del-client')
    resp = client.post('/delete_client/del-client')
    assert resp.status_code == 302


def test_settings_requires_login(client):
    resp = client.get('/settings')
    assert resp.status_code == 302


def test_settings_page_renders(logged_in_client):
    resp = logged_in_client.get('/settings')
    assert resp.status_code == 200
    assert '系统设置' in resp.data.decode('utf-8')


def test_reorder_clients_requires_login(client):
    resp = client.get('/reorder')
    assert resp.status_code == 302


def test_manage_announcements_requires_login(client):
    resp = client.get('/announcements')
    assert resp.status_code == 302


def test_manage_announcements_page_renders(logged_in_client):
    resp = logged_in_client.get('/announcements')
    assert resp.status_code == 200


def test_add_announcement(logged_in_client, app):
    resp = logged_in_client.post('/announcements',
                                 data={'action': 'add', 'title': 'Test', 'content': 'Hello', 'priority': '0'},
                                 follow_redirects=True)
    assert resp.status_code == 200
    from server import Announcement
    with app.app_context():
        a = Announcement.query.filter_by(title='Test').first()
    assert a is not None


def test_export_config(logged_in_client):
    resp = logged_in_client.post('/export_config', follow_redirects=True)
    assert resp.status_code == 200


def test_clear_cache(logged_in_client, app):
    from server import client_realtime_data
    client_realtime_data['dummy'] = {'gpu': []}
    resp = logged_in_client.post('/clear_cache', follow_redirects=True)
    assert resp.status_code == 200
    assert 'dummy' not in client_realtime_data
