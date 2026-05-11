"""Phase 1: GpuUserHourlyUsage ingest 单元测试。"""
import pytest
from datetime import datetime, timedelta


def make_proc(user='alice', gpu_index=0, mem_mb=4096.0, util_pct=35.0):
    return {'user': user, 'gpu_index': gpu_index,
            'mem_mb': mem_mb, 'util_pct': util_pct}


@pytest.fixture
def ingest(app):
    from gpu_report import ingest_user_hourly_sample
    from server import db, Client
    hour = datetime(2026, 5, 11, 14, 0, 0)

    with app.app_context():
        if not db.session.get(Client, 'client-u01'):
            c = Client(id='client-u01', hostname='u-host', ip_address='10.0.1.1',
                       display_name='u-host', platform='linux', display_order=0)
            db.session.add(c)
            db.session.commit()

    def _ingest(proc, ts=None):
        with app.app_context():
            ingest_user_hourly_sample('client-u01', proc, ts or hour)
            db.session.commit()

    return _ingest, hour


@pytest.fixture
def query_row(app):
    def _q(user='alice', gpu_index=0, hour=None):
        from gpu_report import GpuUserHourlyUsage
        if hour is None:
            hour = datetime(2026, 5, 11, 14, 0, 0)
        return GpuUserHourlyUsage.query.filter_by(
            client_id='client-u01', gpu_index=gpu_index,
            user_name=user, hour=hour).first()
    return _q


# ─── basic ───────────────────────────────────────────────────────────────────

def test_first_sample_creates_row(app, ingest, query_row):
    _ingest, _ = ingest
    _ingest(make_proc(mem_mb=4096, util_pct=50))
    with app.app_context():
        row = query_row()
    assert row is not None
    assert row.sample_count == 1
    assert abs(row.vram_mb_avg - 4096) < 0.01
    assert abs(row.util_pct_avg - 50) < 0.01
    assert abs(row.vram_mb_peak - 4096) < 0.01
    assert abs(row.util_pct_peak - 50) < 0.01


def test_running_average(app, ingest, query_row):
    _ingest, _ = ingest
    utils = [10.0, 30.0, 50.0, 70.0, 90.0]
    for u in utils:
        _ingest(make_proc(util_pct=u, mem_mb=u * 100))
    with app.app_context():
        row = query_row()
    assert row.sample_count == 5
    assert abs(row.util_pct_avg - sum(utils) / 5) < 0.01
    assert abs(row.vram_mb_peak - 9000) < 0.01
    assert abs(row.util_pct_peak - 90) < 0.01


def test_peak_tracking(app, ingest, query_row):
    _ingest, _ = ingest
    _ingest(make_proc(util_pct=30, mem_mb=2000))
    _ingest(make_proc(util_pct=80, mem_mb=8000))
    _ingest(make_proc(util_pct=50, mem_mb=4000))
    with app.app_context():
        row = query_row()
    assert abs(row.util_pct_peak - 80) < 0.01
    assert abs(row.vram_mb_peak - 8000) < 0.01


# ─── multi-user / multi-gpu isolation ────────────────────────────────────────

def test_different_users_isolated(app, ingest, query_row):
    _ingest, _ = ingest
    _ingest(make_proc(user='alice', mem_mb=4096))
    _ingest(make_proc(user='bob', mem_mb=8192))
    with app.app_context():
        alice = query_row(user='alice')
        bob = query_row(user='bob')
    assert alice.sample_count == 1
    assert bob.sample_count == 1
    assert abs(alice.vram_mb_avg - 4096) < 0.01
    assert abs(bob.vram_mb_avg - 8192) < 0.01


def test_different_gpus_isolated(app, ingest, query_row):
    _ingest, _ = ingest
    _ingest(make_proc(gpu_index=0, mem_mb=4096))
    _ingest(make_proc(gpu_index=1, mem_mb=8192))
    with app.app_context():
        g0 = query_row(gpu_index=0)
        g1 = query_row(gpu_index=1)
    assert g0.sample_count == 1
    assert g1.sample_count == 1


# ─── hour bucketing ──────────────────────────────────────────────────────────

def test_hour_bucket_truncation(app, ingest):
    _ingest, _ = ingest
    base = datetime(2026, 5, 11, 14, 0, 0)
    _ingest(make_proc(util_pct=10), ts=base)
    _ingest(make_proc(util_pct=20), ts=base + timedelta(minutes=59, seconds=59))
    _ingest(make_proc(util_pct=30), ts=base + timedelta(hours=1))

    from gpu_report import GpuUserHourlyUsage
    with app.app_context():
        h14 = GpuUserHourlyUsage.query.filter_by(
            client_id='client-u01', user_name='alice',
            hour=datetime(2026, 5, 11, 14, 0, 0)).first()
        h15 = GpuUserHourlyUsage.query.filter_by(
            client_id='client-u01', user_name='alice',
            hour=datetime(2026, 5, 11, 15, 0, 0)).first()
    assert h14.sample_count == 2
    assert h15.sample_count == 1


# ─── defensive parsing ──────────────────────────────────────────────────────

def test_missing_user_field_defaults_to_unknown(app, ingest, query_row):
    _ingest, _ = ingest
    _ingest({'gpu_index': 0, 'mem_mb': 2048, 'util_pct': 10})
    with app.app_context():
        row = query_row(user='__unknown__')
    assert row is not None
    assert row.sample_count == 1


def test_user_name_alias_accepted(app, ingest, query_row):
    """支持 user 或 user_name 两个键名 (向后兼容)。"""
    _ingest, _ = ingest
    _ingest({'user_name': 'charlie', 'gpu_index': 0,
             'mem_mb': 1024, 'util_pct': 5})
    with app.app_context():
        row = query_row(user='charlie')
    assert row is not None


def test_invalid_numeric_silently_skipped(app, ingest, query_row):
    _ingest, _ = ingest
    _ingest({'user': 'alice', 'gpu_index': 'not-a-number',
             'mem_mb': 1024, 'util_pct': 10})
    with app.app_context():
        # 没有任何 row 写入
        from gpu_report import GpuUserHourlyUsage
        rows = GpuUserHourlyUsage.query.filter_by(client_id='client-u01').all()
    assert rows == []


# ─── /report integration: payload without gpu_processes still works ─────────

def test_report_endpoint_accepts_payload_without_gpu_processes(app, client):
    """老 client(不发 gpu_processes) /report 不应该报错或污染新表。"""
    from server import db, Client
    from gpu_report import GpuUserHourlyUsage

    payload = {
        'client_id': 'legacy-001',
        'hostname': 'legacy-host',
        'ip_address': '10.0.2.1',
        'platform': 'linux',
        'timestamp': datetime.now().isoformat(),
        'cpu': {'count': 4, 'usage_percent': 20},
        'memory': {'total': 8e9, 'used': 4e9, 'percent': 50},
        'disks': [],
        'gpu': [],
        'uptime_seconds': 1000,
    }
    resp = client.post('/report', json=payload)
    assert resp.status_code == 200
    with app.app_context():
        assert GpuUserHourlyUsage.query.count() == 0


def test_report_endpoint_writes_user_samples_when_present(app, client):
    from gpu_report import GpuUserHourlyUsage

    payload = {
        'client_id': 'new-001',
        'hostname': 'new-host',
        'ip_address': '10.0.2.2',
        'platform': 'linux',
        'timestamp': datetime.now().isoformat(),
        'client_version': '0511-1',
        'cpu': {'count': 4, 'usage_percent': 20},
        'memory': {'total': 8e9, 'used': 4e9, 'percent': 50},
        'disks': [],
        'gpu': [],
        'uptime_seconds': 1000,
        'gpu_processes': [
            {'user': 'alice', 'gpu_index': 0, 'mem_mb': 4096, 'util_pct': 40},
            {'user': 'bob',   'gpu_index': 0, 'mem_mb': 2048, 'util_pct': 15},
        ],
    }
    resp = client.post('/report', json=payload)
    assert resp.status_code == 200
    with app.app_context():
        rows = GpuUserHourlyUsage.query.filter_by(client_id='new-001').all()
        users = sorted(r.user_name for r in rows)
    assert users == ['alice', 'bob']
