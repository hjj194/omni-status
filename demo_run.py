"""Boot the demo server with seeded data on port 5050.

This populates realtime in-memory data IN-PROCESS so the running
server can render it on dashboard / gpu-report.
"""
import os
import sys
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
DEMO_DB = os.path.join(HERE, 'demo.db')
os.environ['FLASK_TESTING_DB'] = f'sqlite:///{DEMO_DB}'
sys.path.insert(0, os.path.join(HERE, 'server'))

from server import app, db, init_db, Client, client_realtime_data  # noqa: E402

with app.app_context():
    init_db()

# If DB is empty, run the seed script to populate it
with app.app_context():
    if Client.query.count() == 0:
        print("[demo] empty DB, running demo_seed.py first...")
        seed_path = os.path.join(HERE, 'demo_seed.py')
        with open(seed_path) as f:
            exec(f.read(), {'__name__': '__main__', '__file__': seed_path})

# Always (re)populate in-memory realtime data — this is process-local
# and gets wiped between invocations
RT_SPECS = {
    'demo-srv-01': [(0, 'RTX 3090', 'ok', 85, 22000, 24576),
                     (1, 'RTX 3090', 'ok', 78, 19500, 24576),
                     (2, 'RTX 3090', 'ok', 90, 23000, 24576),
                     (3, 'RTX 3090', 'ok', 82, 20000, 24576)],
    'demo-srv-02': [(0, 'RTX 4090', 'ok', 5,  500,  24576),
                     (1, 'RTX 4090', 'ok', 70, 17000, 24576)],
    'demo-srv-03': [(0, 'A100',     'ok', 60, 50000, 81920),
                     (1, 'A100',     'error', 0, 0, 0)],
    'demo-srv-04': [(0, 'RTX 3090', 'ok', 3,  100,  24576),
                     (1, 'RTX 3090', 'ok', 8,  200,  24576)],
    'demo-srv-05': [(0, 'RTX 4090', 'ok', 2,  80,   24576)],
}

now = datetime.now()
with app.app_context():
    for cid, gpus in RT_SPECS.items():
        client = Client.query.get(cid)
        if not client:
            continue
        client.last_seen = now
        gpu_list = []
        gpu_last_ok = {}
        for idx, name, status, util, mem_used, mem_total in gpus:
            if status == 'error':
                gpu_list.append({
                    'index': idx, 'name': name, 'status': 'error',
                    'error': 'nvidia-smi: [N/A] (XID 31 — driver hung)',
                    'timestamp': now.isoformat(),
                })
                gpu_last_ok[idx] = now - timedelta(minutes=14)
            else:
                gpu_list.append({
                    'index': idx, 'name': name, 'status': 'ok',
                    'utilization': util, 'memory_used': mem_used,
                    'memory_total': mem_total,
                })
                gpu_last_ok[idx] = now
        client_realtime_data[cid] = {
            'timestamp': now,
            'cpu': {'count': 64, 'usage_percent': 25.0 + 5 * len(gpus)},
            'memory': {'total': 137 * 1024**3,
                        'used': 40 * 1024**3, 'percent': 30.0},
            'disks': [{'device': '/dev/sda', 'mountpoint': '/',
                       'total': 1000 * 1024**3, 'used': 500 * 1024**3, 'percent': 50.0}],
            'gpu': gpu_list,
            'gpu_last_ok': gpu_last_ok,
            'uptime_seconds': 7 * 24 * 3600 + 3600,
        }
    db.session.commit()

print("\n" + "=" * 60)
print("  omni-status demo server")
print("=" * 60)
print(f"  Dashboard:   http://127.0.0.1:5050/")
print(f"  Login:       http://127.0.0.1:5050/login   (admin / admin)")
print(f"  GPU Report:  http://127.0.0.1:5050/gpu-report  (after login)")
print("=" * 60)
with app.app_context():
    n_clients = Client.query.count()
print(f"  Seeded {n_clients} clients, {len(client_realtime_data)} with realtime data")
print("=" * 60 + "\n")

app.run(host='127.0.0.1', port=5050, debug=False)
