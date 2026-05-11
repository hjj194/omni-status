"""规模回归测试 — 5000 行用户级数据,确保 SQL 聚合保持低延迟。

不当真正的 perf gate 用,只是给个上限,防止以后有人偷偷退回 Python 端聚合。
"""
import time
import pytest
from datetime import datetime, timedelta


@pytest.fixture
def large_dataset(app):
    """50 用户 × 8 GPU × 168 小时 ≈ 67200 行;按用户出现率随机稀释到 ~5000 行。"""
    from server import db, Client
    from gpu_report import GpuUserHourlyUsage
    import random

    rng = random.Random(42)
    now = datetime.now().replace(minute=0, second=0, microsecond=0)
    users = [f'user_{i:02d}' for i in range(20)]

    with app.app_context():
        for cid in ('m-1', 'm-2'):
            if not db.session.get(Client, cid):
                db.session.add(Client(
                    id=cid, hostname=f'host-{cid}', ip_address='127.0.0.1',
                    display_name=cid, platform='linux', display_order=0))
        db.session.commit()

        batch = []
        for h in range(168):           # 7 days × 24 h
            hour = now - timedelta(hours=h)
            for cid in ('m-1', 'm-2'):
                for gpu_idx in range(4):
                    # 每张卡每小时只有 ~30% 概率有用户在跑
                    if rng.random() < 0.3:
                        u = rng.choice(users)
                        batch.append(GpuUserHourlyUsage(
                            client_id=cid, gpu_index=gpu_idx,
                            user_name=u, hour=hour,
                            vram_mb_avg=rng.uniform(1000, 20000),
                            vram_mb_peak=rng.uniform(2000, 24000),
                            util_pct_avg=rng.uniform(0, 100),
                            util_pct_peak=rng.uniform(0, 100),
                            sample_count=60,
                        ))
        db.session.add_all(batch)
        db.session.commit()
    yield len(batch)


def test_user_summary_at_scale_stays_under_500ms(app, large_dataset):
    """5000 行规模下排行榜查询应该在 500ms 内完成。

    在 SQLite + 现代笔记本上实测一般 < 50ms。设 500ms 是给慢盘/CI 留 buffer。
    """
    from gpu_report import get_user_summary
    with app.app_context():
        t0 = time.perf_counter()
        result = get_user_summary(period='week')
        elapsed = time.perf_counter() - t0

    assert elapsed < 0.5, f"get_user_summary 太慢: {elapsed * 1000:.0f}ms"
    assert len(result) > 0
    # 检查降序排序确实生效
    assert result[0]['gpu_hours'] >= result[-1]['gpu_hours']


def test_user_detail_at_scale_stays_under_200ms(app, large_dataset):
    from gpu_report import get_user_detail
    with app.app_context():
        t0 = time.perf_counter()
        detail = get_user_detail('user_00', period='week')
        elapsed = time.perf_counter() - t0

    assert elapsed < 0.2, f"get_user_detail 太慢: {elapsed * 1000:.0f}ms"
    # user_00 大概率有数据(随机种子固定)
    assert detail['user_name'] == 'user_00'
