"""Phase 4: 保留策略与级联删除测试。"""
import pytest
from datetime import datetime, timedelta


def _make_client(app, cid='cli-001'):
    from server import db, Client
    with app.app_context():
        c = Client(id=cid, hostname='host', ip_address='1.2.3.4',
                   display_name='host', platform='linux', display_order=0)
        db.session.add(c)
        db.session.commit()
    return cid


def _insert_rows(app, client_id, hours_ago_list):
    """按 hours_ago_list 插入 GpuHourlyUsage 行。"""
    from gpu_report import GpuHourlyUsage
    from server import db
    now = datetime.now().replace(minute=0, second=0, microsecond=0)
    with app.app_context():
        for h in hours_ago_list:
            row = GpuHourlyUsage(
                client_id=client_id,
                gpu_index=0,
                hour=now - timedelta(hours=h),
                gpu_name='RTX',
                vram_pct_avg=50.0,
                ok_sample_count=10,
            )
            db.session.add(row)
        db.session.commit()


def test_cleanup_deletes_rows_older_than_7d(app):
    cid = _make_client(app)
    # 5 rows within 7 days, 5 rows older
    _insert_rows(app, cid, list(range(1, 6)) + list(range(170, 175)))

    from gpu_report import cleanup_hourly, GpuHourlyUsage
    with app.app_context():
        app.config['GPU_REPORT']['retention_days'] = 7
        cleanup_hourly()
        count = GpuHourlyUsage.query.filter_by(client_id=cid).count()
    assert count == 5


def test_cleanup_keeps_exactly_7d_boundary(app):
    from gpu_report import GpuHourlyUsage
    from server import db
    cid = _make_client(app)
    now = datetime.now().replace(minute=0, second=0, microsecond=0)
    boundary = now - timedelta(days=7)

    with app.app_context():
        # borderline: 1 second inside → keep; boundary itself → delete by strict <
        keep_row = GpuHourlyUsage(
            client_id=cid, gpu_index=0,
            hour=boundary + timedelta(hours=1),  # 6d 23h ago → keep
            gpu_name='RTX', vram_pct_avg=10.0, ok_sample_count=1,
        )
        del_row = GpuHourlyUsage(
            client_id=cid, gpu_index=1,
            hour=boundary - timedelta(hours=1),  # 7d 1h ago → delete
            gpu_name='RTX', vram_pct_avg=10.0, ok_sample_count=1,
        )
        db.session.add_all([keep_row, del_row])
        db.session.commit()

        from gpu_report import cleanup_hourly
        app.config['GPU_REPORT']['retention_days'] = 7
        cleanup_hourly()

        rows = GpuHourlyUsage.query.filter_by(client_id=cid).all()
    assert len(rows) == 1
    assert rows[0].gpu_index == 0


def test_cleanup_llm_reports_keeps_latest_12(app):
    from gpu_report import LlmReport, cleanup_llm_reports
    from server import db
    with app.app_context():
        base = datetime(2026, 1, 1)
        for i in range(20):
            db.session.add(LlmReport(
                generated_at=base + timedelta(days=i),
                period_start=base,
                period_end=base + timedelta(days=7),
                status='ok', content=f'report {i}',
            ))
        db.session.commit()
        app.config['GPU_REPORT']['llm_report_retention'] = 12
        cleanup_llm_reports()
        count = LlmReport.query.count()
    assert count == 12


def test_client_delete_cascades_gpu_hourly_usage(app):
    from gpu_report import GpuHourlyUsage
    from server import db, Client
    cid = _make_client(app, 'cascade-client')
    _insert_rows(app, cid, [1, 2, 3])

    with app.app_context():
        pre = GpuHourlyUsage.query.filter_by(client_id=cid).count()
        assert pre == 3
        client = Client.query.get(cid)
        db.session.delete(client)
        db.session.commit()
        post = GpuHourlyUsage.query.filter_by(client_id=cid).count()
    assert post == 0
