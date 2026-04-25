"""Seed demo data so /gpu-report has rich content to display.

Usage:
  cd server && python ../demo_seed.py
"""
import os
import sys
import random
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'server'))

# Use a dedicated demo DB so we don't touch any real data
os.environ.setdefault('FLASK_TESTING_DB', f"sqlite:///{os.path.join(HERE, 'demo.db')}")

from server import app, db, Client, init_db  # noqa: E402
from gpu_report import GpuHourlyUsage, LlmReport, ingest_hourly_sample  # noqa: E402
from server import client_realtime_data  # noqa: E402

with app.app_context():
    init_db()

DEMO_CLIENTS = [
    # (id, hostname, display_name, gpus)
    ('demo-srv-01', 'lab-srv-01', 'lab-srv-01 (RTX 3090 ×4)',  4),
    ('demo-srv-02', 'lab-srv-02', 'lab-srv-02 (RTX 4090 ×2)',  2),
    ('demo-srv-03', 'lab-srv-03', 'lab-srv-03 (A100 ×2,1 卡 XID 错误)', 2),
    ('demo-srv-04', 'lab-srv-04', 'lab-srv-04 (RTX 3090 ×2,长期空闲)', 2),
    ('demo-srv-05', 'lab-srv-05', 'lab-srv-05 (RTX 4090 ×1)', 1),
]


def seed():
    with app.app_context():
        # Clean prior demo data
        GpuHourlyUsage.query.delete()
        LlmReport.query.delete()
        Client.query.delete()
        db.session.commit()
        client_realtime_data.clear()

        now = datetime.now()

        # Create clients
        for i, (cid, hostname, display, n_gpus) in enumerate(DEMO_CLIENTS):
            c = Client(
                id=cid, hostname=hostname, ip_address=f'10.0.0.{10 + i}',
                display_name=display, platform='Linux 5.15.0', display_order=i,
                physical_address=f'机柜 {chr(ord("A") + i)}',
            )
            c.last_seen = now
            db.session.add(c)
        db.session.commit()

        # Seed 168 hours (7 days) of GpuHourlyUsage
        for cid, hostname, _disp, n_gpus in DEMO_CLIENTS:
            for gpu_idx in range(n_gpus):
                for h_offset in range(168):
                    hour = (now.replace(minute=0, second=0, microsecond=0)
                            - timedelta(hours=h_offset))

                    if cid == 'demo-srv-01':
                        # 高利用率训练机:大部分时间 70-95% VRAM
                        vram = random.uniform(70, 95)
                        util = random.uniform(60, 90)
                        err = 0
                    elif cid == 'demo-srv-02':
                        # 间歇训练:有 idle 也有 busy
                        if h_offset % 6 < 2:
                            vram, util = random.uniform(5, 20), random.uniform(0, 10)
                        else:
                            vram, util = random.uniform(60, 85), random.uniform(50, 80)
                        err = 0
                    elif cid == 'demo-srv-03':
                        # 第二张卡近 24h XID 错误
                        if gpu_idx == 1 and h_offset < 24:
                            vram, util = 0, 0
                            err = random.randint(40, 60)
                        else:
                            vram, util = random.uniform(40, 80), random.uniform(30, 70)
                            err = 0
                    elif cid == 'demo-srv-04':
                        # 长期空闲机:VRAM 持续低
                        vram = random.uniform(2, 12)
                        util = random.uniform(0, 5)
                        err = 0
                    else:
                        # demo-srv-05:近 4h 空闲,之前在用
                        if h_offset < 4:
                            vram, util = random.uniform(3, 10), random.uniform(0, 5)
                        else:
                            vram, util = random.uniform(50, 80), random.uniform(40, 70)
                        err = 0

                    row = GpuHourlyUsage(
                        client_id=cid, gpu_index=gpu_idx, hour=hour,
                        gpu_name=f'GPU-{cid}-{gpu_idx}',
                        vram_pct_avg=round(vram, 2),
                        vram_pct_peak=round(min(100, vram * 1.1), 2),
                        util_pct_avg=round(util, 2),
                        util_pct_peak=round(min(100, util * 1.15), 2),
                        ok_sample_count=60 if err == 0 else max(0, 60 - err),
                        error_count=err,
                    )
                    db.session.add(row)
        db.session.commit()

        # Seed realtime data (in-memory) for current dashboard + idle list
        rt_specs = {
            'demo-srv-01': [(0, 'RTX 3090', 'ok', 85, 22000, 24576),
                             (1, 'RTX 3090', 'ok', 78, 19500, 24576),
                             (2, 'RTX 3090', 'ok', 90, 23000, 24576),
                             (3, 'RTX 3090', 'ok', 82, 20000, 24576)],
            'demo-srv-02': [(0, 'RTX 4090', 'ok', 5,  500,  24576),  # 空闲
                             (1, 'RTX 4090', 'ok', 70, 17000, 24576)],
            'demo-srv-03': [(0, 'A100',     'ok', 60, 50000, 81920),
                             (1, 'A100',     'error', 0, 0, 0)],     # XID
            'demo-srv-04': [(0, 'RTX 3090', 'ok', 3,  100,  24576),  # 长期空
                             (1, 'RTX 3090', 'ok', 8,  200,  24576)], # 长期空
            'demo-srv-05': [(0, 'RTX 4090', 'ok', 2,  80,   24576)], # 空闲
        }

        for cid, gpus in rt_specs.items():
            gpu_list = []
            gpu_last_ok = {}
            for idx, name, status, util, mem_used, mem_total in gpus:
                if status == 'error':
                    gpu_list.append({
                        'index': idx, 'name': name, 'status': 'error',
                        'error': 'nvidia-smi: [N/A] (XID 31 — driver hung)',
                        'timestamp': now.isoformat(),
                    })
                    # Last OK was 14 minutes ago
                    gpu_last_ok[idx] = now - timedelta(minutes=14)
                else:
                    gpu_list.append({
                        'index': idx, 'name': name, 'status': 'ok',
                        'utilization': util,
                        'memory_used': mem_used, 'memory_total': mem_total,
                    })
                    gpu_last_ok[idx] = now
            client_realtime_data[cid] = {
                'timestamp': now,
                'cpu': {'count': 64, 'usage_percent': random.uniform(15, 60)},
                'memory': {'total': 137 * 1024**3,
                            'used': int(40 * 1024**3 * random.uniform(0.8, 1.2)),
                            'percent': random.uniform(25, 60)},
                'disks': [{'device': '/dev/sda', 'mountpoint': '/',
                           'total': 1000 * 1024**3, 'used': 500 * 1024**3, 'percent': 50.0}],
                'gpu': gpu_list,
                'gpu_last_ok': gpu_last_ok,
                'uptime_seconds': 7 * 24 * 3600 + 3600,
            }

        # Seed an LLM weekly summary
        sample_summary = """\
## 本周实验室 GPU 使用周报

**整体趋势**:实验室 GPU 整体利用率较为均衡,综合利用率约 **52%**(较上周持平)。

**长期空闲 GPU**:
- **lab-srv-04 GPU 0/1**(RTX 3090):过去 7 天 VRAM 均值仅 7%,168 小时全部低占用,可能存在调度或访问障碍,建议核查
- **lab-srv-02 GPU 0**(RTX 4090):间歇空闲约 56 小时,可考虑承接小规模训练任务

**硬件异常**:
- **lab-srv-03 GPU 1**(A100):过去 24 小时出现 6 次 nvidia-smi `[N/A]` 异常(XID 31),建议现场检查驱动与硬件

**当前可立即调度的 GPU**:**4 张**(lab-srv-02 GPU 0、lab-srv-04 GPU 0/1、lab-srv-05 GPU 0)
"""
        db.session.add(LlmReport(
            generated_at=now - timedelta(hours=2),
            period_start=now - timedelta(days=7),
            period_end=now,
            model='claude-haiku-4-5-20251001',
            status='ok', content=sample_summary,
            input_tokens=1450, output_tokens=320,
        ))
        db.session.commit()

        print(f"\n✅ Demo data seeded:")
        print(f"   Clients:           {Client.query.count()}")
        print(f"   GpuHourlyUsage:    {GpuHourlyUsage.query.count()} rows ({168*11} expected)")
        print(f"   LlmReport:         {LlmReport.query.count()}")
        print(f"   Realtime entries:  {len(client_realtime_data)}")


if __name__ == '__main__':
    seed()
