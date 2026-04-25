"""补充 server.py 剩余路由覆盖。"""
import json
import pytest
from datetime import datetime


def report(client, client_id='srv-x'):
    payload = {
        'client_id': client_id,
        'timestamp': datetime.now().isoformat(),
        'hostname': 'host-x',
        'ip_address': '10.0.0.50',
        'platform': 'Linux',
        'cpu': {'count': 4, 'usage_percent': 10.0},
        'memory': {'total': 4 * 1024 ** 3, 'used': 1 * 1024 ** 3, 'percent': 25.0},
        'disks': [{'device': '/dev/sda', 'mountpoint': '/', 'total': 100 * 1024 ** 3,
                   'used': 40 * 1024 ** 3, 'percent': 40.0}],
        'gpu': [],
        'uptime_seconds': 500,
    }
    return client.post('/report', data=json.dumps(payload), content_type='application/json')


def test_reorder_get_requires_login(client):
    resp = client.get('/reorder')
    assert resp.status_code == 302


def test_reorder_get_renders(logged_in_client):
    resp = logged_in_client.get('/reorder')
    assert resp.status_code == 200


def test_reorder_post(app, logged_in_client):
    report(logged_in_client, 'reorder-a')
    report(logged_in_client, 'reorder-b')
    resp = logged_in_client.post('/reorder',
                                 data={'client_ids[]': ['reorder-b', 'reorder-a']},
                                 follow_redirects=True)
    assert resp.status_code == 200
    from server import Client
    with app.app_context():
        a = Client.query.get('reorder-a')
        b = Client.query.get('reorder-b')
    assert b.display_order < a.display_order


def test_announcement_toggle(logged_in_client, app):
    from server import Announcement, db
    with app.app_context():
        a = Announcement(title='Toggle Test', content='...', is_active=True)
        db.session.add(a)
        db.session.commit()
        aid = a.id

    resp = logged_in_client.post('/announcements',
                                 data={'action': 'toggle', 'announcement_id': str(aid)},
                                 follow_redirects=True)
    assert resp.status_code == 200
    with app.app_context():
        toggled = Announcement.query.get(aid)
    assert toggled.is_active is False


def test_announcement_delete(logged_in_client, app):
    from server import Announcement, db
    with app.app_context():
        a = Announcement(title='Delete Me', content='bye')
        db.session.add(a)
        db.session.commit()
        aid = a.id

    resp = logged_in_client.post('/announcements',
                                 data={'action': 'delete', 'announcement_id': str(aid)},
                                 follow_redirects=True)
    assert resp.status_code == 200
    with app.app_context():
        gone = Announcement.query.get(aid)
    assert gone is None


def test_edit_announcement_get(logged_in_client, app):
    from server import Announcement, db
    with app.app_context():
        a = Announcement(title='Edit Me', content='original')
        db.session.add(a)
        db.session.commit()
        aid = a.id

    resp = logged_in_client.get(f'/edit_announcement/{aid}')
    assert resp.status_code == 200


def test_edit_announcement_post(logged_in_client, app):
    from server import Announcement, db
    with app.app_context():
        a = Announcement(title='Old', content='old content')
        db.session.add(a)
        db.session.commit()
        aid = a.id

    logged_in_client.post(f'/edit_announcement/{aid}',
                          data={'title': 'New', 'content': 'new content', 'priority': '3'},
                          follow_redirects=True)
    with app.app_context():
        updated = Announcement.query.get(aid)
    assert updated.title == 'New'
    assert updated.priority == 3


def test_settings_password_change_success(logged_in_client, app):
    resp = logged_in_client.post('/settings',
                                 data={'current_password': 'admin',
                                       'new_password': 'newpass123',
                                       'confirm_password': 'newpass123'},
                                 follow_redirects=True)
    assert resp.status_code == 200
    # reset password back
    logged_in_client.post('/settings',
                          data={'current_password': 'newpass123',
                                'new_password': 'admin',
                                'confirm_password': 'admin'},
                          follow_redirects=True)


def test_settings_password_mismatch(logged_in_client):
    resp = logged_in_client.post('/settings',
                                 data={'current_password': 'admin',
                                       'new_password': 'new1',
                                       'confirm_password': 'new2'},
                                 follow_redirects=True)
    assert resp.status_code == 200


def test_settings_wrong_current_password(logged_in_client):
    resp = logged_in_client.post('/settings',
                                 data={'current_password': 'wrong',
                                       'new_password': 'new123',
                                       'confirm_password': 'new123'},
                                 follow_redirects=True)
    assert resp.status_code == 200


def test_delete_client_logged_in(logged_in_client, app):
    report(logged_in_client, 'del-cl-x')
    resp = logged_in_client.post('/delete_client/del-cl-x', follow_redirects=True)
    assert resp.status_code == 200
    from server import Client
    with app.app_context():
        assert Client.query.get('del-cl-x') is None


def test_import_config_logged_in(logged_in_client):
    resp = logged_in_client.post('/import_config', follow_redirects=True)
    assert resp.status_code == 200
