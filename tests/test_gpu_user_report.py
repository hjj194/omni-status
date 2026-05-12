"""Phase 3: 用户级 GPU 报表 — 查询函数 + 路由 + CSV 导出测试。"""
import pytest
from datetime import datetime, timedelta


@pytest.fixture
def seed_users(app):
    """造一批用户级数据,横跨多天多用户多卡。"""
    from server import db, Client
    from gpu_report import GpuUserHourlyUsage

    now = datetime.now().replace(minute=0, second=0, microsecond=0)
    with app.app_context():
        for cid in ('lab-A', 'lab-B'):
            if not db.session.get(Client, cid):
                c = Client(id=cid, hostname=f'{cid}-host', ip_address=f'10.0.{cid[-1]}.1',
                           display_name=cid.upper(), platform='linux', display_order=0)
                db.session.add(c)
        db.session.commit()

        # alice: 在 lab-A GPU 0 上密集使用 24 小时,平均 util 高
        for h in range(24):
            db.session.add(GpuUserHourlyUsage(
                client_id='lab-A', gpu_index=0, user_name='alice',
                hour=now - timedelta(hours=h),
                vram_mb_avg=8000, vram_mb_peak=10000,
                util_pct_avg=60, util_pct_peak=80,
                sample_count=60,
            ))
        # bob: 在 lab-A GPU 1 上挂了 12 小时但都是低利用率 → 空跑
        for h in range(12):
            db.session.add(GpuUserHourlyUsage(
                client_id='lab-A', gpu_index=1, user_name='bob',
                hour=now - timedelta(hours=h),
                vram_mb_avg=2000, vram_mb_peak=2100,
                util_pct_avg=3, util_pct_peak=5,
                sample_count=60,
            ))
        # bob 同时在 lab-B GPU 0 上 6 小时,正常使用
        for h in range(6):
            db.session.add(GpuUserHourlyUsage(
                client_id='lab-B', gpu_index=0, user_name='bob',
                hour=now - timedelta(hours=h),
                vram_mb_avg=4000, vram_mb_peak=5000,
                util_pct_avg=45, util_pct_peak=55,
                sample_count=60,
            ))
        # 老旧数据(40天前): 不应出现在本周/本月排行
        db.session.add(GpuUserHourlyUsage(
            client_id='lab-A', gpu_index=0, user_name='ancient',
            hour=now - timedelta(days=40),
            vram_mb_avg=999, vram_mb_peak=999,
            util_pct_avg=99, util_pct_peak=99, sample_count=60,
        ))
        db.session.commit()
    yield


# ─── queries: get_user_summary ───────────────────────────────────────────────

def test_summary_ranks_by_gpu_hours(app, seed_users):
    from gpu_report import get_user_summary
    with app.app_context():
        result = get_user_summary(period='week')

    users = [r['user_name'] for r in result]
    # alice 有 24 小时,bob 有 18 (12+6) 小时
    assert users[0] == 'alice'
    assert users[1] == 'bob'
    assert 'ancient' not in users   # 在窗口外


def test_summary_idle_hours_uses_threshold(app, seed_users):
    from gpu_report import get_user_summary
    with app.app_context():
        result = get_user_summary(period='week')
        by_user = {r['user_name']: r for r in result}

    # 阈值默认 10:bob 在 lab-A 的 12 小时 util=3 全部空跑,lab-B 的 6 小时 util=45 不算
    assert by_user['bob']['idle_hours'] == 12
    # alice 全部 util=60,不空跑
    assert by_user['alice']['idle_hours'] == 0


def test_summary_gpu_count_distinct(app, seed_users):
    from gpu_report import get_user_summary
    with app.app_context():
        result = get_user_summary(period='week')
        by_user = {r['user_name']: r for r in result}

    # bob 用了 lab-A:1 和 lab-B:0 两个 GPU
    assert by_user['bob']['gpu_count'] == 2
    assert by_user['alice']['gpu_count'] == 1


def test_summary_month_window_includes_ancient_in_30day_window(app, seed_users):
    """40 天前的数据在 month=30 天窗口外。"""
    from gpu_report import get_user_summary
    with app.app_context():
        result = get_user_summary(period='month')
        users = [r['user_name'] for r in result]
    assert 'ancient' not in users


def test_summary_empty_when_no_data(app):
    from gpu_report import get_user_summary
    with app.app_context():
        assert get_user_summary(period='week') == []


# ─── queries: get_user_detail ────────────────────────────────────────────────

def test_user_detail_groups_by_machine_gpu(app, seed_users):
    from gpu_report import get_user_detail
    with app.app_context():
        detail = get_user_detail('bob', period='week')

    assert detail['user_name'] == 'bob'
    assert detail['total_gpu_hours'] == 18  # 12 + 6
    assert detail['idle_hours'] == 12
    machine_keys = {(m['client_id'], m['gpu_index']) for m in detail['machines']}
    assert machine_keys == {('lab-A', 1), ('lab-B', 0)}


def test_user_detail_unknown_user_returns_empty(app, seed_users):
    from gpu_report import get_user_detail
    with app.app_context():
        detail = get_user_detail('does-not-exist', period='week')
    assert detail['total_gpu_hours'] == 0
    assert detail['machines'] == []


def test_user_detail_includes_display_name(app, seed_users):
    from gpu_report import get_user_detail
    with app.app_context():
        detail = get_user_detail('alice', period='week')
    assert detail['machines'][0]['display_name'] == 'LAB-A'


# ─── views: routes ───────────────────────────────────────────────────────────

def test_users_page_requires_login(client):
    resp = client.get('/gpu-report/users', follow_redirects=False)
    # 没登录会被 login_required 重定向到 /login
    assert resp.status_code in (302, 401)


def test_users_page_renders(logged_in_client, seed_users):
    resp = logged_in_client.get('/gpu-report/users')
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'alice' in body
    assert 'bob' in body


def test_users_page_with_no_data_shows_empty_state(logged_in_client):
    resp = logged_in_client.get('/gpu-report/users')
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert '暂无用户级 GPU 用量数据' in body


def test_user_detail_page_renders(logged_in_client, seed_users):
    resp = logged_in_client.get('/gpu-report/users/alice')
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'alice' in body
    assert 'LAB-A' in body


def test_user_detail_page_for_unknown_user_still_renders(logged_in_client):
    resp = logged_in_client.get('/gpu-report/users/nonexistent')
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert '没有这位用户的 GPU 使用记录' in body


# ─── views: CSV export ───────────────────────────────────────────────────────

def test_users_csv_export(logged_in_client, seed_users):
    resp = logged_in_client.get('/gpu-report/users.csv')
    assert resp.status_code == 200
    assert resp.mimetype == 'text/csv'
    assert 'attachment' in resp.headers.get('Content-Disposition', '')
    body = resp.get_data(as_text=True)
    lines = body.strip().split('\n')
    # 第一行是 header
    assert lines[0].startswith('user_name,')
    # 后面两行是 alice 和 bob
    assert any('alice' in line for line in lines[1:])
    assert any('bob' in line for line in lines[1:])


def test_users_csv_period_in_filename(logged_in_client, seed_users):
    resp = logged_in_client.get('/gpu-report/users.csv?period=month')
    cd = resp.headers.get('Content-Disposition', '')
    assert 'gpu_users_month.csv' in cd


def test_users_csv_invalid_period_falls_back_to_week(logged_in_client, seed_users):
    resp = logged_in_client.get('/gpu-report/users.csv?period=garbage')
    cd = resp.headers.get('Content-Disposition', '')
    assert 'gpu_users_week.csv' in cd


# ─── CSV formula injection (security hardening) ──────────────────────────────

def test_csv_export_quotes_formula_prefix_in_username(app, logged_in_client):
    """如果 user_name 以 = + - @ \\t \\r 开头(就算 ingest 阶段没拦住,
    比如未来直接写库的工具绕过),CSV 导出必须加单引号兜底。"""
    from server import db, Client
    from gpu_report import GpuUserHourlyUsage
    from datetime import datetime, timedelta

    with app.app_context():
        if not db.session.get(Client, 'csv-test'):
            db.session.add(Client(
                id='csv-test', hostname='csv-test', ip_address='1.1.1.1',
                display_name='CSV', platform='linux', display_order=0))
        db.session.commit()
        now = datetime.now().replace(minute=0, second=0, microsecond=0)
        for evil in ('=cmd|"calc"!A1', '+SUM(A1:A2)', '-1+1', '@SUM(1)'):
            db.session.add(GpuUserHourlyUsage(
                client_id='csv-test', gpu_index=0, user_name=evil,
                hour=now - timedelta(hours=1),
                vram_mb_avg=1000, vram_mb_peak=1000,
                util_pct_avg=50, util_pct_peak=50,
                sample_count=60,
            ))
        db.session.commit()

    resp = logged_in_client.get('/gpu-report/users.csv')
    body = resp.get_data(as_text=True)
    # 单元格值不能以裸的 = + - @ 开头
    for line in body.strip().split('\n')[1:]:
        first_cell = line.split(',')[0]
        # csv module 会用 " 包裹含特殊字符的值,所以剥一下
        stripped = first_cell.lstrip('"')
        assert not stripped.startswith(('=', '+', '-', '@')), \
            f"未转义的公式触发字符: {first_cell!r}"


# ─── /report token constant-time compare ─────────────────────────────────────

def test_report_token_constant_time_compare_rejects_wrong_token(app, client):
    """token 错误返回 401,不泄露具体匹配进度。"""
    from datetime import datetime
    # 临时设置 token 校验
    with app.app_context():
        from server import config as server_config
        original = server_config.get('report_token', '')
        server_config['report_token'] = 'correct-token-xyz'
    try:
        payload = {
            'client_id': 'tok-test', 'hostname': 'h', 'ip_address': '1.1.1.1',
            'platform': 'linux', 'timestamp': datetime.now().isoformat(),
            'cpu': {'count': 1, 'usage_percent': 0},
            'memory': {'total': 1, 'used': 0, 'percent': 0},
            'disks': [], 'gpu': [], 'uptime_seconds': 1,
        }
        resp_wrong = client.post('/report', json=payload,
                                 headers={'Authorization': 'Bearer wrong'})
        resp_right = client.post('/report', json=payload,
                                 headers={'Authorization': 'Bearer correct-token-xyz'})
        assert resp_wrong.status_code == 401
        assert resp_right.status_code == 200
    finally:
        with app.app_context():
            from server import config as server_config
            server_config['report_token'] = original


# ─── export endpoint redaction ───────────────────────────────────────────────

def test_runtime_settings_export_redacts_api_key(app, logged_in_client):
    """API key 不能通过 /settings/export/runtime_settings.json 泄露。"""
    import json as _json
    with app.app_context():
        from gpu_report import save_runtime_settings
        save_runtime_settings({'llm_api_key': 'sk-supersecret123'}, app=app)

    resp = logged_in_client.get('/settings/export/runtime_settings.json')
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    parsed = _json.loads(body)
    assert 'llm_api_key' not in parsed
    assert 'sk-supersecret123' not in body
