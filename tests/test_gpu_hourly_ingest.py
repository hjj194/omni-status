"""Phase 2: GpuHourlyUsage ingest 单元测试。"""
import pytest
from datetime import datetime, timedelta


def make_ok_gpu(index=0, util=50.0, mem_used=10000.0, mem_total=24576.0, name='RTX 3090'):
    return {'index': index, 'name': name, 'status': 'ok',
            'utilization': util, 'memory_used': mem_used, 'memory_total': mem_total}


def make_err_gpu(index=1, error='[N/A]'):
    return {'index': index, 'name': 'RTX 3090', 'status': 'error', 'error': error}


@pytest.fixture
def ingest(app):
    from gpu_report import ingest_hourly_sample
    from server import db, Client
    hour = datetime(2026, 4, 24, 14, 0, 0)

    with app.app_context():
        if not db.session.get(Client, 'client-001'):
            c = Client(id='client-001', hostname='test-host', ip_address='10.0.0.1',
                       display_name='test', platform='linux', display_order=0)
            db.session.add(c)
            db.session.commit()

    def _ingest(gpu, ts=None):
        with app.app_context():
            ingest_hourly_sample('client-001', gpu, ts or hour)
            db.session.commit()

    return _ingest, hour


@pytest.fixture
def query_row(app):
    def _q(hour=None, gpu_index=0):
        from gpu_report import GpuHourlyUsage
        if hour is None:
            hour = datetime(2026, 4, 24, 14, 0, 0)
        return GpuHourlyUsage.query.filter_by(
            client_id='client-001', gpu_index=gpu_index, hour=hour).first()
    return _q


# ─── basic ok ────────────────────────────────────────────────────────────────

def test_ingest_ok_sample_creates_row(app, ingest, query_row):
    _ingest, hour = ingest
    _ingest(make_ok_gpu(util=60.0, mem_used=12000.0))
    with app.app_context():
        row = query_row()
    assert row is not None
    assert row.ok_sample_count == 1
    assert row.error_count == 0
    expected_vram = 12000.0 / 24576.0 * 100
    assert abs(row.vram_pct_avg - expected_vram) < 0.01


def test_ingest_ok_sample_updates_existing_row(app, ingest, query_row):
    _ingest, _ = ingest
    _ingest(make_ok_gpu(util=40.0, mem_used=8000.0))
    _ingest(make_ok_gpu(util=60.0, mem_used=16000.0))
    with app.app_context():
        row = query_row()
    assert row.ok_sample_count == 2
    # avg of two VRAM%
    expected = (8000 / 24576 * 100 + 16000 / 24576 * 100) / 2
    assert abs(row.vram_pct_avg - expected) < 0.05


def test_ingest_running_average_converges(app, ingest, query_row):
    _ingest, _ = ingest
    utils = [float(i) for i in range(1, 61)]  # 1..60
    for u in utils:
        _ingest(make_ok_gpu(util=u, mem_used=u * 100))
    with app.app_context():
        row = query_row()
    expected_util = sum(utils) / len(utils)
    assert abs(row.util_pct_avg - expected_util) < 0.01
    assert row.ok_sample_count == 60


def test_ingest_peak_tracking(app, ingest, query_row):
    _ingest, _ = ingest
    _ingest(make_ok_gpu(util=30.0, mem_used=7000.0))
    _ingest(make_ok_gpu(util=80.0, mem_used=20000.0))
    _ingest(make_ok_gpu(util=50.0, mem_used=12000.0))
    with app.app_context():
        row = query_row()
    assert abs(row.util_pct_peak - 80.0) < 0.01
    assert abs(row.vram_pct_peak - 20000 / 24576 * 100) < 0.01


# ─── error samples ───────────────────────────────────────────────────────────

def test_ingest_errored_sample_increments_error_count(app, ingest, query_row):
    _ingest, _ = ingest
    _ingest(make_err_gpu(index=0))  # use same index as ok gpu for simplicity
    with app.app_context():
        row = query_row(gpu_index=0)
    assert row is not None
    assert row.error_count == 1
    assert row.ok_sample_count == 0


def test_ingest_errored_sample_does_not_touch_averages(app, ingest, query_row):
    _ingest, _ = ingest
    _ingest(make_ok_gpu(index=0, util=50.0, mem_used=12000.0))
    before_avg = None
    with app.app_context():
        before_avg = query_row(gpu_index=0).vram_pct_avg
    _ingest(make_err_gpu(index=0))  # same GPU, now errors
    with app.app_context():
        row = query_row(gpu_index=0)
    assert abs(row.vram_pct_avg - before_avg) < 0.001
    assert row.error_count == 1
    assert row.ok_sample_count == 1


# ─── edge cases ──────────────────────────────────────────────────────────────

def test_ingest_division_by_zero_memory_total_treated_as_error(app, ingest, query_row):
    _ingest, _ = ingest
    gpu = {'index': 0, 'name': 'RTX 3090', 'status': 'ok',
           'utilization': 50.0, 'memory_used': 0, 'memory_total': 0}
    _ingest(gpu)
    with app.app_context():
        row = query_row()
    assert row.error_count == 1
    assert row.ok_sample_count == 0


def test_ingest_missing_status_treated_as_ok(app, ingest, query_row):
    """向后兼容:旧客户端不发 status 字段,视作 ok。"""
    _ingest, _ = ingest
    gpu = {'index': 0, 'name': 'RTX 3090',
           'utilization': 40.0, 'memory_used': 8000.0, 'memory_total': 24576.0}
    _ingest(gpu)
    with app.app_context():
        row = query_row()
    assert row.ok_sample_count == 1
    assert row.error_count == 0


def test_hour_bucket_truncation(app):
    """14:59:59 和 14:00:00 落到同一个 14:00 桶;15:00:00 落到 15:00 桶。"""
    from gpu_report import ingest_hourly_sample, GpuHourlyUsage
    from server import db, Client
    gpu = make_ok_gpu(util=10.0, mem_used=2000.0)

    with app.app_context():
        if not db.session.get(Client, 'client-ts'):
            c = Client(id='client-ts', hostname='ts-host', ip_address='10.0.0.2',
                       display_name='ts', platform='linux', display_order=99)
            db.session.add(c)
            db.session.commit()

        ingest_hourly_sample('client-ts', gpu, datetime(2026, 4, 24, 14, 0, 0))
        ingest_hourly_sample('client-ts', gpu, datetime(2026, 4, 24, 14, 59, 59))
        ingest_hourly_sample('client-ts', gpu, datetime(2026, 4, 24, 15, 0, 0))
        db.session.commit()

        h14 = GpuHourlyUsage.query.filter_by(
            client_id='client-ts', hour=datetime(2026, 4, 24, 14, 0, 0)).first()
        h15 = GpuHourlyUsage.query.filter_by(
            client_id='client-ts', hour=datetime(2026, 4, 24, 15, 0, 0)).first()

    assert h14 is not None and h14.ok_sample_count == 2
    assert h15 is not None and h15.ok_sample_count == 1


def test_ingest_gpu_name_updates_on_each_call(app, ingest, query_row):
    _ingest, _ = ingest
    _ingest(make_ok_gpu(name='Old Name'))
    _ingest(make_ok_gpu(name='New Name'))
    with app.app_context():
        row = query_row()
    assert row.gpu_name == 'New Name'
