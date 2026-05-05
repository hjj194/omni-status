import sys
import os

# 环境变量必须在 import server 之前设置
os.environ['FLASK_TESTING_DB'] = 'sqlite:///:memory:'

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER_DIR   = os.path.join(PROJECT_ROOT, 'server')
CLIENT_DIR   = os.path.join(PROJECT_ROOT, 'client')

sys.path.insert(0, SERVER_DIR)
sys.path.insert(0, CLIENT_DIR)

import pytest
from sqlalchemy import event
from server import app as flask_app, db, init_db
import gpu_report  # 确保 GpuHourlyUsage / LlmReport 模型注册进 db.metadata


@pytest.fixture(scope='session')
def app():
    flask_app.config['TESTING'] = True
    flask_app.config['WTF_CSRF_ENABLED'] = False
    flask_app.config['GPU_REPORT'] = {
        'retention_days': 7,
        'idle_vram_threshold': 15,
        'heatmap_low_threshold': 20,
        'heatmap_high_threshold': 70,
        'longterm_vram_threshold': 20,
        'longterm_hours_required': 120,
        'llm_model': 'claude-haiku-4-5-20251001',
        'llm_report_retention': 12,
    }

    with flask_app.app_context():
        # 启用 SQLite 外键约束(级联删除测试需要,需要在 app context 内注册)
        @event.listens_for(db.engine, 'connect')
        def _set_sqlite_pragma(dbapi_conn, _):
            dbapi_conn.execute('PRAGMA foreign_keys=ON')

        init_db()
        yield flask_app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def logged_in_client(app, client):
    """登录后的 admin client。

    默认场景:admin 已经"完成首次改密",可以访问所有路径。
    专门测"强制改密"流程的测试不要用这个 fixture,直接 client.post('/login',...)。
    """
    with app.app_context():
        from server import User
        admin = User.query.filter_by(username='admin').first()
        if admin and admin.must_change_password:
            admin.must_change_password = False
            db.session.commit()
    client.post('/login',
                data={'username': 'admin', 'password': 'admin'},
                follow_redirects=True)
    return client


@pytest.fixture(autouse=True)
def clean_db(app):
    """每个测试后清理业务数据(保留 admin user)。"""
    yield
    with app.app_context():
        from gpu_report import GpuHourlyUsage, LlmReport
        from server import Client, Announcement, UptimeRecord, client_realtime_data, User
        GpuHourlyUsage.query.delete()
        LlmReport.query.delete()
        Client.query.delete()
        Announcement.query.delete()
        UptimeRecord.query.delete()
        # 还原 admin must_change_password = True,保证下个测试隔离
        admin = User.query.filter_by(username='admin').first()
        if admin:
            admin.set_password('admin')   # 重置密码；set_password 内部会把 must_change_password 设为 False
            admin.must_change_password = True  # 必须在 set_password 之后再设，否则被覆盖
        db.session.commit()
        client_realtime_data.clear()
        # Reset GPU_REPORT config to defaults to prevent state pollution between tests
        from gpu_report.config import DEFAULT_CFG
        app.config['GPU_REPORT'] = dict(DEFAULT_CFG)
        app.config['GPU_REPORT'].update({
            'retention_days': 7, 'idle_vram_threshold': 15,
            'heatmap_low_threshold': 20, 'heatmap_high_threshold': 70,
            'longterm_vram_threshold': 20, 'longterm_hours_required': 120,
            'llm_model': 'claude-haiku-4-5-20251001', 'llm_report_retention': 12,
            'llm_provider': 'anthropic', 'llm_api_key': '', 'llm_base_url': '',
        })


@pytest.fixture
def reset_nvidia_cache():
    """每个客户端 GPU 解析测试前重置可用性缓存。"""
    import client as client_module
    client_module._nvidia_available = None
    yield
    client_module._nvidia_available = None
