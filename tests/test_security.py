"""Wave 1 安全加固:rate limit / token 鉴权 / SECRET_KEY / 上传上限。"""
import json
import os
import pytest
from datetime import datetime


def base_payload(client_id='sec-cli'):
    return {
        'client_id': client_id,
        'timestamp': datetime.now().isoformat(),
        'hostname': 'sec-host', 'ip_address': '10.0.0.1',
        'platform': 'Linux',
        'cpu': {'count': 4, 'usage_percent': 10.0},
        'memory': {'total': 1024, 'used': 256, 'percent': 25.0},
        'disks': [{'device': '/dev/sda', 'mountpoint': '/',
                   'total': 100, 'used': 40, 'percent': 40.0}],
        'gpu': [], 'uptime_seconds': 100,
    }


# ─── /report token 鉴权 ──────────────────────────────────────────────

def test_report_no_token_required_when_unconfigured(client):
    """默认 (config 无 report_token) 时 /report 不强制鉴权(向后兼容)。"""
    resp = client.post('/report', data=json.dumps(base_payload('no-tok')),
                        content_type='application/json')
    assert resp.status_code == 200


def test_report_rejects_missing_token_when_configured(app, client):
    """配置了 report_token 后,缺 token 的请求被 401。"""
    import server as server_mod
    orig = server_mod.config.get('report_token', '')
    server_mod.config['report_token'] = 'sekret-12345'
    try:
        resp = client.post('/report', data=json.dumps(base_payload('need-tok')),
                            content_type='application/json')
        assert resp.status_code == 401
    finally:
        server_mod.config['report_token'] = orig


def test_report_accepts_valid_bearer_token(app, client):
    import server as server_mod
    orig = server_mod.config.get('report_token', '')
    server_mod.config['report_token'] = 'good-token'
    try:
        resp = client.post('/report',
                            data=json.dumps(base_payload('with-tok')),
                            content_type='application/json',
                            headers={'Authorization': 'Bearer good-token'})
        assert resp.status_code == 200
    finally:
        server_mod.config['report_token'] = orig


def test_report_rejects_wrong_token(app, client):
    import server as server_mod
    orig = server_mod.config.get('report_token', '')
    server_mod.config['report_token'] = 'good-token'
    try:
        resp = client.post('/report',
                            data=json.dumps(base_payload('bad-tok')),
                            content_type='application/json',
                            headers={'Authorization': 'Bearer wrong-token'})
        assert resp.status_code == 401
    finally:
        server_mod.config['report_token'] = orig


def test_report_accepts_x_report_token_header_alternative(app, client):
    """允许 X-Report-Token 头(不便用 Bearer 时的备选)。"""
    import server as server_mod
    orig = server_mod.config.get('report_token', '')
    server_mod.config['report_token'] = 'alt-tok'
    try:
        resp = client.post('/report',
                            data=json.dumps(base_payload('x-hdr')),
                            content_type='application/json',
                            headers={'X-Report-Token': 'alt-tok'})
        assert resp.status_code == 200
    finally:
        server_mod.config['report_token'] = orig


# ─── 上传大小限制 ──────────────────────────────────────────────────────

def test_max_content_length_configured(app):
    assert app.config['MAX_CONTENT_LENGTH'] == 100 * 1024 * 1024


def test_oversized_upload_rejected_413(logged_in_client):
    """伪造一个大于 100 MB 的文件流,/import/db 应该 413。"""
    huge = b'A' * (101 * 1024 * 1024)
    resp = logged_in_client.post('/settings/import/db',
                                  data={'db_file': (
                                      __import__('io').BytesIO(huge), 'big.db')},
                                  content_type='multipart/form-data')
    # Werkzeug 在 max_content_length 超限时返回 413
    assert resp.status_code == 413


# ─── /login rate limit ───────────────────────────────────────────────

def test_limiter_disabled_in_tests(app):
    """测试环境下 limiter 应该是关掉的,免得测试套件互相干扰。"""
    from server import limiter
    assert limiter.enabled is False


# ─── 客户端支持 ──────────────────────────────────────────────────────

def test_client_report_to_server_sends_bearer_token():
    import client as c
    from unittest.mock import patch, MagicMock
    mock_resp = MagicMock(status_code=200)
    with patch('requests.post', return_value=mock_resp) as mock_post:
        c.report_to_server('http://localhost:5000/report', {'k': 'v'},
                            report_token='my-tok')
    assert mock_post.called
    headers = mock_post.call_args.kwargs.get('headers', {})
    assert headers.get('Authorization') == 'Bearer my-tok'


def test_client_report_to_server_no_header_when_no_token():
    import client as c
    from unittest.mock import patch, MagicMock
    mock_resp = MagicMock(status_code=200)
    with patch('requests.post', return_value=mock_resp) as mock_post:
        c.report_to_server('http://localhost:5000/report', {'k': 'v'})
    headers = mock_post.call_args.kwargs.get('headers', {})
    assert 'Authorization' not in headers


def test_client_handles_401_explicitly():
    import client as c
    from unittest.mock import patch, MagicMock
    mock_resp = MagicMock(status_code=401, text='unauthorized')
    with patch('requests.post', return_value=mock_resp):
        result = c.report_to_server('http://localhost:5000/report', {},
                                     report_token='wrong')
    assert result is False


# ─── 客户端版本上报 ────────────────────────────────────────────────

def test_client_payload_includes_version():
    import client as c
    info = c.get_system_info('test-uuid')
    assert info['client_version'] == c.CLIENT_VERSION
    assert isinstance(info['client_version'], str)
    assert len(info['client_version']) > 0


def test_server_persists_client_version(app, client):
    payload = base_payload('ver-cli')
    payload['client_version'] = '0426-1'
    resp = client.post('/report', data=json.dumps(payload),
                        content_type='application/json')
    assert resp.status_code == 200

    from server import Client as ClientModel, db
    with app.app_context():
        c = db.session.get(ClientModel, 'ver-cli')
        assert c.client_version == '0426-1'


def test_server_keeps_old_version_when_payload_missing(app, client):
    """老客户端 payload 没 client_version 时,不应清掉已有的版本号。"""
    from server import Client as ClientModel, db
    with app.app_context():
        c = ClientModel(id='legacy-cli', hostname='legacy', ip_address='10.0.0.50',
                        display_name='legacy', platform='linux',
                        display_order=0, client_version='OLD-VERSION')
        db.session.add(c)
        db.session.commit()

    payload = base_payload('legacy-cli')
    # explicitly do NOT include client_version (mimics old client)
    client.post('/report', data=json.dumps(payload), content_type='application/json')

    with app.app_context():
        c = db.session.get(ClientModel, 'legacy-cli')
        assert c.client_version == 'OLD-VERSION'  # 仍然是旧值,不被清掉


# ─── 强制首次改密 ────────────────────────────────────────────────────

def test_default_admin_marked_must_change_password(app):
    from server import User
    with app.app_context():
        admin = User.query.filter_by(username='admin').first()
        assert admin is not None
        assert admin.must_change_password is True


def test_login_with_default_password_redirects_to_settings(app, client):
    """admin/admin 登录后,被重定向到 /settings 强制改密。"""
    resp = client.post('/login',
                        data={'username': 'admin', 'password': 'admin'},
                        follow_redirects=False)
    assert resp.status_code == 302
    assert '/settings' in resp.headers.get('Location', '')


def test_admin_protected_routes_redirect_when_must_change(app, client):
    """登录后但 must_change_password=True 的会话访问 /announcements 被踢回 /settings。"""
    client.post('/login', data={'username': 'admin', 'password': 'admin'})
    resp = client.get('/announcements', follow_redirects=False)
    assert resp.status_code == 302
    assert '/settings' in resp.headers.get('Location', '')


def test_password_change_clears_must_change_flag(app, client):
    """改密后,must_change_password 被清掉,可访问其它管理路径。"""
    client.post('/login', data={'username': 'admin', 'password': 'admin'})
    # 改密
    client.post('/settings', data={
        'current_password': 'admin',
        'new_password': 'new-password-123',
        'confirm_password': 'new-password-123',
    }, follow_redirects=True)
    # 现在可以访问别的页面
    resp = client.get('/announcements')
    assert resp.status_code == 200
    # 验证 DB 也清掉了 flag
    from server import User, db
    with app.app_context():
        admin = User.query.filter_by(username='admin').first()
        assert admin.must_change_password is False
    # 还原密码,免影响别的测试
    client.post('/settings', data={
        'current_password': 'new-password-123',
        'new_password': 'admin',
        'confirm_password': 'admin',
    }, follow_redirects=True)


def test_force_change_settings_page_hides_full_layout(app, client):
    """must_change_password=True 时 /settings GET 只渲染最小改密页,
    不暴露 LLM 配置 / 存储统计 / 清理按钮等信息。"""
    client.post('/login', data={'username': 'admin', 'password': 'admin'})
    resp = client.get('/settings')
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # 最小页面有改密表单
    assert '修改管理员密码' in body
    assert 'current_password' in body
    # 但不包含完整设置页特有内容
    assert 'storage' not in body.lower() or '存储统计' not in body
    # 完整页 LLM 配置块和保留策略块都不应出现
    assert 'llm_api_key' not in body
    assert 'save_retention' not in body
    assert 'cleanup_gpu_hourly' not in body
    assert 'export/db' not in body
    # 不需要手动还原:conftest.clean_db fixture 每个测试结束都会重置 admin。


def test_dashboard_shows_upgrade_badge_for_outdated_client(app, client):
    """当客户端版本 ≠ 服务端期望版本时,dashboard 显示"待升级" badge。"""
    from server import Client as ClientModel, db, client_realtime_data, EXPECTED_CLIENT_VERSION
    with app.app_context():
        c = ClientModel(id='old-ver', hostname='oldhost', ip_address='10.0.0.51',
                        display_name='oldhost', platform='linux',
                        display_order=0, client_version='OLDVER-X',
                        last_seen=datetime.now())
        db.session.add(c)
        db.session.commit()
    client_realtime_data['old-ver'] = {
        'gpu': [], 'gpu_last_ok': {},
        'cpu': {'count': 4, 'usage_percent': 5},
        'memory': {'percent': 10, 'used': 100, 'total': 1000},
        'disks': [{'mountpoint': 'Total', 'percent': 50, 'used': 50, 'total': 100}],
        'uptime_seconds': 100, 'timestamp': datetime.now(),
    }
    resp = client.get('/')
    html = resp.data.decode()
    assert 'OLDVER-X' in html or '待升级' in html
