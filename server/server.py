#!/usr/bin/env python3
import sys
# 以 `python server.py` 启动时模块注册为 __main__，但 gpu_report/models.py 做
# `from server import db` 时找不到 server，触发循环 import。
# 提前将本模块注册为 'server'，让子包能安全地引用 db。
if __name__ == '__main__':
    sys.modules.setdefault('server', sys.modules['__main__'])

from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash, send_file, Response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta, date as date_type
from werkzeug.security import generate_password_hash, check_password_hash
import functools
import json
import os
import logging
from logging.handlers import RotatingFileHandler
import configparser
from auth import login_required

# 配置日志（带轮转，最大 10MB，保留 5 份备份）
def _make_log_handler():
    for candidate in [
        os.path.join('/var/log/system-monitor', 'server.log'),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'server.log'),
    ]:
        try:
            os.makedirs(os.path.dirname(candidate), exist_ok=True)
            h = RotatingFileHandler(candidate, maxBytes=10 * 1024 * 1024, backupCount=5)
            h.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
            return h
        except (PermissionError, OSError):
            continue
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    return h

_log_handler = _make_log_handler()
logging.basicConfig(level=logging.INFO, handlers=[_log_handler])
# Werkzeug 默认每个请求都打 INFO,客户端每分钟上报一次会把日志刷爆;
# 只保留 WARNING 及以上(404/500 等)
logging.getLogger('werkzeug').setLevel(logging.WARNING)
logger = logging.getLogger('system_monitor_server')

# 配置文件路径（使用绝对路径）
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'server_config.json')

# 获取配置
def load_config():
    config = configparser.ConfigParser()
    config_file = '/etc/system-monitor/server/server.conf'
    
    # 默认配置
    default_config = {
        'host': '0.0.0.0',
        'port': 5000,
        'secret_key': os.environ.get('SECRET_KEY', 'dev_key_change_in_production'),
        'debug': False,
        # /report 共享密钥;留空表示不强制(过渡兼容旧客户端)
        'report_token': os.environ.get('REPORT_TOKEN', ''),
    }
    
    if os.path.exists(config_file):
        try:
            config.read(config_file)
            server_config = config['server'] if 'server' in config else {}
            # 合并配置
            for key in default_config:
                if key not in server_config:
                    server_config[key] = default_config[key]
            
            return {
                'host': server_config.get('host'),
                'port': int(server_config.get('port')),
                'secret_key': server_config.get('secret_key'),
                'debug': server_config.getboolean('debug'),
                'report_token': server_config.get('report_token', '') or '',
            }
        except Exception as e:
            logger.error(f"加载配置文件失败: {e}")
    
    logger.warning("使用默认配置")
    return default_config

# 保存客户端配置到文件
def save_client_configs():
    """将客户端配置信息保存到文件"""
    try:
        clients = Client.query.all()
        client_configs = []
        
        for client in clients:
            client_configs.append({
                'id': client.id,
                'hostname': client.hostname,
                'ip_address': client.ip_address,
                'physical_address': client.physical_address,
                'display_name': client.display_name,
                'notes': client.notes,
                'platform': client.platform,
                'display_order': client.display_order
            })
        
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(client_configs, f, ensure_ascii=False, indent=2)
        
        logger.info(f"客户端配置已保存到 {CONFIG_FILE}")
        return True
    except Exception as e:
        logger.error(f"保存客户端配置失败: {e}")
        return False

# 从文件加载客户端配置
def load_client_configs():
    """从文件加载客户端配置信息"""
    try:
        if not os.path.exists(CONFIG_FILE):
            logger.info("配置文件不存在，跳过加载")
            return False
        
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            client_configs = json.load(f)
        
        for config in client_configs:
            existing_client = db.session.get(Client, config['id'])
            if existing_client:
                # 更新现有客户端的配置信息（仅更新管理员设置的字段）
                existing_client.physical_address = config.get('physical_address')
                existing_client.display_name = config.get('display_name')
                existing_client.notes = config.get('notes')
                existing_client.display_order = config.get('display_order', 0)
            else:
                # 创建新的客户端记录（从备份恢复）
                new_client = Client(
                    id=config['id'],
                    hostname=config['hostname'],
                    ip_address=config['ip_address'],
                    physical_address=config.get('physical_address'),
                    display_name=config.get('display_name'),
                    notes=config.get('notes'),
                    platform=config.get('platform'),
                    display_order=config.get('display_order', 0),
                    last_seen=None  # 这个会在客户端下次连接时更新
                )
                db.session.add(new_client)
        
        db.session.commit()
        logger.info(f"从 {CONFIG_FILE} 加载了 {len(client_configs)} 个客户端配置")
        return True
    except Exception as e:
        logger.error(f"加载客户端配置失败: {e}")
        return False

# 加载配置
config = load_config()

# ─── SECRET_KEY 启动校验 ──────────────────────────────────────────────
# 测试环境(FLASK_TESTING_DB 已设)允许默认 key 通过,生产必须显式设置
INSECURE_DEFAULT_KEYS = {'dev_key_change_in_production', '', None}
_is_testing = bool(os.environ.get('FLASK_TESTING_DB'))
if not _is_testing and config['secret_key'] in INSECURE_DEFAULT_KEYS:
    raise RuntimeError(
        "\n  ❌ SECRET_KEY 不能使用默认值!\n"
        "  生成一个强随机 key:\n"
        "    python -c \"import secrets; print(secrets.token_hex(32))\"\n"
        "  然后写入 /etc/system-monitor/server/server.conf 的 [server] secret_key = ...\n"
        "  或设置环境变量 SECRET_KEY=...\n"
    )

# 配置Flask应用
app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = config['secret_key']  # 用于session
# 上传文件大小上限(防止恶意大文件 DoS)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB

# 测试时可通过环境变量覆盖为 sqlite:///:memory:
_test_db = os.environ.get('FLASK_TESTING_DB')
if _test_db:
    app.config['SQLALCHEMY_DATABASE_URI'] = _test_db
else:
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'monitor.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'

db = SQLAlchemy(app)

# ─── SQLite 性能 pragmas ─────────────────────────────────────────────────
# WAL: 写锁不阻塞读,大幅缓解多 client 并发上报时的锁竞争
# synchronous=NORMAL: WAL 模式下足够安全(掉电最多丢最后几秒数据,监控场景可接受)
# cache_size=-64000: 64MB 页缓存,报表页扫几千行小时数据基本全 in-memory
# foreign_keys=ON: 启用 CASCADE 删除(模型里依赖 ondelete='CASCADE')
#
# 监听全局 Engine 类而不是 db.engine,避免在模块导入时触发 app-context 依赖。
# 仅对 SQLite 后端生效,Postgres 等其他后端会跳过。
from sqlalchemy import event  # noqa: E402
from sqlalchemy.engine import Engine  # noqa: E402

@event.listens_for(Engine, 'connect')
def _set_sqlite_pragmas(dbapi_conn, _):
    if 'sqlite3' not in type(dbapi_conn).__module__.lower():
        return
    cursor = dbapi_conn.cursor()
    cursor.execute('PRAGMA journal_mode=WAL')
    cursor.execute('PRAGMA synchronous=NORMAL')
    cursor.execute('PRAGMA cache_size=-64000')
    cursor.execute('PRAGMA foreign_keys=ON')
    cursor.close()

# 服务端期望的最低客户端版本(用于 dashboard 标识"待升级"机器)
EXPECTED_CLIENT_VERSION = '0426-1'

# ─── 速率限制 ──────────────────────────────────────────────────────────
from flask_limiter import Limiter  # noqa: E402
from flask_limiter.util import get_remote_address  # noqa: E402

# 测试环境关掉 rate limit,免得测试套件互相打架
_limiter_enabled = not _is_testing
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["1000 per hour"],          # 全局兜底
    storage_uri="memory://",                    # 单进程足够;多 worker 改 redis
    enabled=_limiter_enabled,
)

# ─── CSRF 保护 ────────────────────────────────────────────────────────
from flask_wtf.csrf import CSRFProtect  # noqa: E402

# 测试环境关掉 CSRF,生产强制
app.config['WTF_CSRF_ENABLED'] = not _is_testing
csrf = CSRFProtect(app)

# ─── 数据库迁移 ──────────────────────────────────────────────────────
# Flask-Migrate 让 schema 演进可追踪、可回滚。当前 init_db() 仍然是
# 主入口(自带 idempotent ALTER 兜底);未来新增字段统一走:
#   FLASK_APP=server.py flask db migrate -m "add foo column"
#   FLASK_APP=server.py flask db upgrade
from flask_migrate import Migrate  # noqa: E402
migrate = Migrate(app, db, directory=os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'migrations'))

# 数据模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    must_change_password = db.Column(db.Boolean, default=False)  # 首次登录强制改密

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        self.must_change_password = False

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Client(db.Model):
    id = db.Column(db.String(36), primary_key=True)  # 客户端ID
    hostname = db.Column(db.String(100))  # 主机名
    ip_address = db.Column(db.String(50))  # IP地址
    physical_address = db.Column(db.String(100))  # 物理地址 (可编辑)
    display_name = db.Column(db.String(100))  # 显示名称 (可编辑)
    notes = db.Column(db.Text)  # 备注信息 (可编辑)
    platform = db.Column(db.String(200))  # 系统平台信息
    last_seen = db.Column(db.DateTime)  # 最后一次上报时间
    display_order = db.Column(db.Integer, default=0)  # 显示顺序
    client_version = db.Column(db.String(40))  # 客户端版本(用于识别待升级机器)

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)  # 公告标题
    content = db.Column(db.Text, nullable=False)  # 公告内容
    created_at = db.Column(db.DateTime, default=datetime.now)  # 创建时间
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)  # 更新时间
    is_active = db.Column(db.Boolean, default=True)  # 是否启用
    priority = db.Column(db.Integer, default=0)  # 优先级，数值越大越靠前

class UptimeRecord(db.Model):
    """每日在线状态快照，用于历史可用性展示"""
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(36), db.ForeignKey('client.id', ondelete='CASCADE'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    status = db.Column(db.Integer, default=0)  # 0=正常 1=降级 2=中断
    __table_args__ = (db.UniqueConstraint('client_id', 'date', name='uq_uptime_client_date'),)

# 实时数据存储（不持久化到数据库）
client_realtime_data = {}

def _compute_daily_status(data):
    """客户端能上报即视为在线（0=在线）"""
    return 0

def _record_uptime(client_id, data):
    """写入或更新当天的可用性记录（同一天保留最差状态）"""
    today = date_type.today()
    new_status = _compute_daily_status(data)
    record = UptimeRecord.query.filter_by(client_id=client_id, date=today).first()
    if record is None:
        db.session.add(UptimeRecord(client_id=client_id, date=today, status=new_status))
    elif new_status > record.status:
        record.status = new_status

# 创建数据库和初始管理员
def init_db():
    import gpu_report  # noqa: F401 — 触发 GpuHourlyUsage / LlmReport 模型注册
    db.create_all()
    
    # 添加display_order列（如果是旧数据库更新）
    try:
        with db.engine.connect() as conn:
            conn.execute(db.text('ALTER TABLE client ADD COLUMN display_order INTEGER DEFAULT 0'))
            conn.commit()
    except Exception:
        pass  # 如果列已存在则忽略错误

    # 添加client_version列(用于识别待升级机器)
    try:
        with db.engine.connect() as conn:
            conn.execute(db.text('ALTER TABLE client ADD COLUMN client_version VARCHAR(40)'))
            conn.commit()
    except Exception:
        pass
    
    # idempotent ALTER 给老库加 must_change_password 列
    try:
        with db.engine.connect() as conn:
            conn.execute(db.text(
                'ALTER TABLE user ADD COLUMN must_change_password BOOLEAN DEFAULT 0'))
            conn.commit()
    except Exception:
        pass

    # 创建默认管理员账户(标记为必须改密)
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin')
        admin.set_password('admin')   # 默认密码,首次登录强制更换
        admin.must_change_password = True
        db.session.add(admin)
        db.session.commit()
        logger.info("Created default admin user (must change password on first login)")
    
    # 从配置文件加载客户端配置
    load_client_configs()

@app.route('/healthz')
def healthz():
    """Kubernetes / systemd watchdog 健康探针。"""
    try:
        db.session.execute(db.text('SELECT 1'))
        return jsonify({'status': 'ok', 'db': 'ok'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'db': str(e)}), 503


@app.route('/readyz')
def readyz():
    """就绪探针:已有客户端上报过 = 就绪。"""
    try:
        Client.query.count()
        return jsonify({'status': 'ready'}), 200
    except Exception as e:
        return jsonify({'status': 'not_ready', 'error': str(e)}), 503


@app.route('/report', methods=['POST'])
@csrf.exempt  # 机器对机器调用,有自己的 token 鉴权,不走浏览器 CSRF
@limiter.limit("60 per minute")  # 单 IP 每分钟最多 60 次,防爆量
def report():
    """接收客户端上报的数据"""
    # ── /report token 校验(若 server.conf 配了 report_token 就强制) ──
    expected_token = config.get('report_token', '')
    if expected_token:
        auth = request.headers.get('Authorization', '')
        token = (auth.removeprefix('Bearer ').strip()
                 if auth.startswith('Bearer ') else
                 request.headers.get('X-Report-Token', ''))
        if not token or token != expected_token:
            logger.warning(f"/report 鉴权失败 from {request.remote_addr}")
            return jsonify({'error': 'unauthorized'}), 401

    data = request.json
    if not data:
        return jsonify({'error': 'missing JSON body'}), 400
    # 只校验绝对必需的字段；uptime_seconds / gpu 等字段老客户端可能不发，兼容处理
    required = ('client_id', 'hostname', 'ip_address', 'platform',
                'timestamp', 'cpu', 'memory', 'disks')
    missing = [f for f in required if f not in data]
    if missing:
        logger.warning(f"/report 缺少必需字段 {missing} from {request.remote_addr}")
        return jsonify({'error': f'missing fields: {missing}'}), 400

    # 获取或创建客户端记录
    client = db.session.get(Client, data['client_id'])
    is_new_client = client is None
    if is_new_client:
        # 获取最大显示顺序
        max_order = db.session.query(db.func.max(Client.display_order)).scalar() or 0

        client = Client(
            id=data['client_id'],
            hostname=data['hostname'],
            ip_address=data['ip_address'],
            display_name=data['hostname'],  # 默认使用主机名作为显示名
            platform=data['platform'],
            display_order=max_order + 1  # 新客户端添加到末尾
        )
        db.session.add(client)
        logger.info(f"New client registered: {data['hostname']} ({data['ip_address']})")

    # 更新客户端信息
    client.hostname = data['hostname']
    client.ip_address = data['ip_address']
    client.platform = data['platform']
    client.last_seen = datetime.now()
    # 老客户端不发 client_version,沿用旧值;新客户端会覆写
    if data.get('client_version'):
        client.client_version = data['client_version']

    # 保留上次各 GPU 正常读数时间(用于 dashboard 显示)
    existing_rt = client_realtime_data.get(data['client_id'], {})
    gpu_last_ok = dict(existing_rt.get('gpu_last_ok', {}))
    now_ts = datetime.now()
    for gpu in data.get('gpu', []):
        if gpu.get('status', 'ok') != 'error':
            gpu_last_ok[gpu['index']] = now_ts

    # 存储实时数据（不持久化）
    client_realtime_data[data['client_id']] = {
        'timestamp': datetime.fromisoformat(data['timestamp']),
        'cpu': data['cpu'],
        'memory': data['memory'],
        'disks': data['disks'],
        'gpu': data['gpu'],
        'gpu_last_ok': gpu_last_ok,
        'uptime_seconds': data['uptime_seconds']
    }

    # 写入每日可用性快照
    _record_uptime(data['client_id'], data)
    db.session.commit()

    # GPU 小时聚合(独立提交,失败不影响 dashboard)
    try:
        from gpu_report import ingest_hourly_sample
        for gpu in data.get('gpu', []):
            ingest_hourly_sample(data['client_id'], gpu, now_ts)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.warning(f"GPU 小时样本写入失败: {e}")

    # 用户级 GPU 用量聚合(0511+ client 才上报 gpu_processes,老 client 跳过)
    if data.get('gpu_processes'):
        try:
            from gpu_report import ingest_user_hourly_sample
            for proc in data['gpu_processes']:
                ingest_user_hourly_sample(data['client_id'], proc, now_ts)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.warning(f"用户级 GPU 样本写入失败: {e}")

    # 仅当有新客户端注册时保存配置
    if is_new_client:
        save_client_configs()

    return jsonify({"status": "success"})

@app.route('/')
def dashboard():
    """主仪表盘页面"""
    clients = Client.query.order_by(Client.display_order).all()

    # 清理已删除客户端残留的实时数据
    valid_ids = {c.id for c in clients}
    for stale_id in [cid for cid in client_realtime_data if cid not in valid_ids]:
        del client_realtime_data[stale_id]

    client_data = []
    
    for client in clients:
        # 获取实时数据
        realtime_data = client_realtime_data.get(client.id)
        
        if realtime_data:
            # 计算正常运行时间的格式化字符串
            uptime = timedelta(seconds=realtime_data['uptime_seconds'])
            days = uptime.days
            hours, remainder = divmod(uptime.seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            uptime_str = f"{days}天 {hours}小时 {minutes}分钟"
            
            # 检查是否最近报告过 (10分钟内)
            is_online = (datetime.now() - client.last_seen).total_seconds() < 600 if client.last_seen else False
            
            # 只保留根目录的磁盘信息
            filtered_disks = []
            total_disk_info = {
                'device': 'Total Storage',
                'mountpoint': 'Total',
                'total': 0,
                'used': 0,
                'percent': 0
            }
            root_disk = None
            
            for disk in realtime_data['disks']:
                if disk['mountpoint'] == '/':
                    root_disk = disk
                total_disk_info['total'] += disk['total']
                total_disk_info['used'] += disk['used']
            
            # 计算总存储使用百分比
            if total_disk_info['total'] > 0:
                total_disk_info['percent'] = (total_disk_info['used'] / total_disk_info['total']) * 100
            
            # 添加根目录和总存储到过滤后的磁盘列表
            if root_disk:
                filtered_disks.append(root_disk)
            filtered_disks.append(total_disk_info)

            # 为每张 GPU 注入 last_ok_minutes_ago(坏卡展示用)
            gpu_last_ok = realtime_data.get('gpu_last_ok', {})
            now_for_gpu = datetime.now()
            gpu_list = []
            for gpu in realtime_data.get('gpu', []):
                g = dict(gpu)
                if g.get('status') == 'error':
                    last_ok = gpu_last_ok.get(g.get('index'))
                    if last_ok:
                        g['last_ok_minutes_ago'] = int((now_for_gpu - last_ok).total_seconds() // 60)
                    else:
                        g['last_ok_minutes_ago'] = None
                gpu_list.append(g)

            client_data.append({
                'id': client.id,
                'hostname': client.hostname,
                'display_name': client.display_name or client.hostname,
                'ip_address': client.ip_address,
                'physical_address': client.physical_address or '未设置',
                'notes': client.notes,
                'platform': client.platform,
                'last_seen': client.last_seen,
                'is_online': is_online,
                'cpu': realtime_data['cpu'],
                'memory': realtime_data['memory'],
                'disks': filtered_disks,
                'gpu': gpu_list,
                'uptime': uptime_str,
                'display_order': client.display_order,
                'client_version': client.client_version,
            })
        else:
            # 没有实时数据的客户端，显示为离线
            client_data.append({
                'id': client.id,
                'hostname': client.hostname,
                'display_name': client.display_name or client.hostname,
                'ip_address': client.ip_address,
                'physical_address': client.physical_address or '未设置',
                'notes': client.notes,
                'platform': client.platform,
                'last_seen': client.last_seen,
                'is_online': False,
                'cpu': {'usage_percent': 0},
                'memory': {'percent': 0, 'used': 0, 'total': 0},
                'disks': [],
                'gpu': [],
                'uptime': '未知',
                'display_order': client.display_order,
                'client_version': client.client_version,
            })
    
    # 查询所有客户端最近 30 天的可用性记录
    today = date_type.today()
    days_30 = [today - timedelta(days=i) for i in range(29, -1, -1)]
    records = UptimeRecord.query.filter(UptimeRecord.date >= days_30[0]).all()
    uptime_lookup = {}
    for r in records:
        uptime_lookup.setdefault(r.client_id, {})[r.date] = r.status

    # 为每个客户端生成 30 天列表
    for c in client_data:
        day_map = uptime_lookup.get(c['id'], {})
        c['uptime_history'] = [
            {'date': d.strftime('%m-%d'), 'status': day_map.get(d, -1)}
            for d in days_30
        ]

    # 获取公告
    announcements = Announcement.query.filter_by(is_active=True).order_by(Announcement.priority.desc(), Announcement.created_at.desc()).all()

    return render_template('dashboard.html', clients=client_data,
                           is_admin=session.get('logged_in', False),
                           announcements=announcements,
                           expected_client_version=EXPECTED_CLIENT_VERSION)

@app.route('/reorder', methods=['GET', 'POST'])
@login_required
def reorder_clients():
    """重新排序客户端卡片"""
    if request.method == 'POST':
        # 获取新顺序
        client_ids = request.form.getlist('client_ids[]')
        
        # 更新数据库中的顺序
        for i, client_id in enumerate(client_ids):
            client = db.session.get(Client, client_id)
            if client:
                client.display_order = i
        
        db.session.commit()
        
        # 保存配置到文件
        save_client_configs()
        
        flash('客户端显示顺序已更新', 'success')
        return redirect(url_for('dashboard'))
    
    # 获取所有客户端
    clients = Client.query.order_by(Client.display_order).all()
    client_data = []
    
    for client in clients:
        # 检查是否最近报告过 (10分钟内)
        is_online = (datetime.now() - client.last_seen).total_seconds() < 600 if client.last_seen else False
        
        client_data.append({
            'id': client.id,
            'hostname': client.hostname,
            'display_name': client.display_name or client.hostname,
            'ip_address': client.ip_address,
            'physical_address': client.physical_address or '未设置',
            'is_online': is_online,
            'display_order': client.display_order
        })
    
    return render_template('reorder_clients.html', clients=client_data)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("8 per minute; 30 per hour", methods=['POST'],
               error_message="登录尝试过于频繁,请稍后再试")
def login():
    """管理员登录页面"""
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['logged_in'] = True
            session['username'] = username
            session['must_change_password'] = bool(user.must_change_password)
            logger.info(f"Admin login successful: {username}")
            if user.must_change_password:
                flash('使用默认密码登录,请立即修改', 'warning')
                return redirect(url_for('settings'))
            return redirect(url_for('dashboard'))
        else:
            error = '用户名或密码错误'
            logger.warning(f"Failed login attempt for username: {username}")
    
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    """登出"""
    if 'username' in session:
        logger.info(f"Admin logout: {session['username']}")
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('dashboard'))

@app.route('/edit_client/<client_id>', methods=['GET', 'POST'])
@login_required
def edit_client(client_id):
    """编辑客户端信息页面 (需要登录)"""
    client = Client.query.get_or_404(client_id)
    
    if request.method == 'POST':
        client.display_name = request.form.get('display_name')
        client.ip_address = request.form.get('ip_address')
        client.physical_address = request.form.get('physical_address')
        client.notes = request.form.get('notes')
        db.session.commit()
        
        # 保存配置到文件
        save_client_configs()
        
        logger.info(f"Client information updated: {client.hostname} (ID: {client.id})")
        flash('客户端信息已更新', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('edit_client.html', client=client)

@app.route('/delete_client/<client_id>', methods=['POST'])
@login_required
def delete_client(client_id):
    """删除客户端记录 (需要登录)"""
    client = Client.query.get_or_404(client_id)
    hostname = client.hostname

    client_realtime_data.pop(client_id, None)
    db.session.delete(client)
    db.session.commit()
    save_client_configs()

    logger.info(f"Client deleted: {hostname} (ID: {client_id})")
    flash(f'客户端 "{hostname}" 已删除', 'success')
    return redirect(url_for('dashboard'))

# 历史记录功能已移除 - 只保留实时监控

@app.route('/export_config', methods=['POST'])
@login_required
def export_config():
    """导出客户端配置"""
    if save_client_configs():
        flash(f'客户端配置已导出到 {CONFIG_FILE}', 'success')
    else:
        flash('导出配置失败', 'danger')
    return redirect(url_for('settings'))

@app.route('/import_config', methods=['POST'])
@login_required
def import_config():
    """导入客户端配置"""
    if load_client_configs():
        flash('客户端配置已成功导入', 'success')
    else:
        flash('导入配置失败', 'danger')
    return redirect(url_for('settings'))

@app.route('/clear_cache', methods=['POST'])
@login_required
def clear_cache():
    """清除实时数据缓存"""
    global client_realtime_data
    cache_count = len(client_realtime_data)
    client_realtime_data.clear()
    
    flash(f'已清除 {cache_count} 个客户端的实时数据缓存', 'success')
    logger.info(f"Admin {session['username']} cleared realtime data cache, {cache_count} clients affected")
    return redirect(url_for('settings'))

@app.route('/announcements', methods=['GET', 'POST'])
@login_required
def manage_announcements():
    """公告管理页面"""
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add':
            # 添加新公告
            title = request.form.get('title')
            content = request.form.get('content')
            priority = int(request.form.get('priority', 0))
            
            if title and content:
                announcement = Announcement(
                    title=title,
                    content=content,
                    priority=priority
                )
                db.session.add(announcement)
                db.session.commit()
                flash('公告已添加', 'success')
            else:
                flash('标题和内容不能为空', 'danger')
                
        elif action == 'toggle':
            # 切换公告状态
            try:
                announcement_id = int(request.form.get('announcement_id', 0))
            except (ValueError, TypeError):
                announcement_id = 0
            announcement = db.session.get(Announcement, announcement_id)
            if announcement:
                announcement.is_active = not announcement.is_active
                db.session.commit()
                flash(f'公告已{"启用" if announcement.is_active else "禁用"}', 'success')

        elif action == 'delete':
            # 删除公告
            try:
                announcement_id = int(request.form.get('announcement_id', 0))
            except (ValueError, TypeError):
                announcement_id = 0
            announcement = db.session.get(Announcement, announcement_id)
            if announcement:
                db.session.delete(announcement)
                db.session.commit()
                flash('公告已删除', 'success')
        
        return redirect(url_for('manage_announcements'))
    
    # 获取所有公告
    announcements = Announcement.query.order_by(Announcement.priority.desc(), Announcement.created_at.desc()).all()
    return render_template('announcements.html', announcements=announcements)

@app.route('/edit_announcement/<int:announcement_id>', methods=['GET', 'POST'])
@login_required
def edit_announcement(announcement_id):
    """编辑公告"""
    announcement = Announcement.query.get_or_404(announcement_id)
    
    if request.method == 'POST':
        announcement.title = request.form.get('title')
        announcement.content = request.form.get('content')
        announcement.priority = int(request.form.get('priority', 0))
        announcement.updated_at = datetime.now()
        db.session.commit()
        
        flash('公告已更新', 'success')
        return redirect(url_for('manage_announcements'))
    
    return render_template('edit_announcement.html', announcement=announcement)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """系统设置页面"""
    if request.method == 'POST':
        # 处理密码修改
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not new_password or len(new_password) < 8:
            flash('新密码不能为空且长度至少 8 位', 'danger')
            return redirect(url_for('settings'))

        if new_password != confirm_password:
            flash('新密码和确认密码不匹配', 'danger')
            return redirect(url_for('settings'))
            
        user = User.query.filter_by(username=session['username']).first()
        if user and user.check_password(current_password):
            user.set_password(new_password)  # set_password 会自动清 must_change_password
            db.session.commit()
            session.pop('must_change_password', None)
            flash('密码已成功更新', 'success')
            logger.info(f"Password changed for user: {user.username}")
        else:
            flash('当前密码不正确', 'danger')
        
        return redirect(url_for('settings'))
    
    # 获取客户端数量
    client_count = Client.query.count()
    
    # 获取当前时间
    current_time = datetime.now()
    
    # 获取数据库大小（简化版，因为移除了历史记录功能）
    db_size = None
    if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite'):
        db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
        try:
            db_size = os.path.getsize(db_path) / (1024 * 1024)  # MB
        except:
            pass
    
    # 存储统计 + 当前保留策略(用于在 settings 页渲染)
    from gpu_report import get_storage_stats, SETTING_BOUNDS
    storage = get_storage_stats()
    cfg = app.config.get('GPU_REPORT', {})
    retention = {
        'gpu_hourly_days': cfg.get('retention_days', 7),
        'llm_report_count': cfg.get('llm_report_retention', 12),
        'uptime_days': cfg.get('uptime_record_retention_days', 90),
        'bounds': SETTING_BOUNDS,
        # LLM 配置字段
        'llm_provider':       cfg.get('llm_provider', 'anthropic'),
        'llm_base_url':       cfg.get('llm_base_url', ''),
        'llm_model':          cfg.get('llm_model', 'claude-haiku-4-5-20251001'),
        'llm_schedule_cron':  cfg.get('llm_schedule_cron', '0 9 * * 1'),
        # API key 来源状态(给模板显示标签)
        'api_key_from_env':   bool(os.environ.get('ANTHROPIC_API_KEY', '').strip()),
        'api_key_stored':     bool(cfg.get('llm_api_key', '').strip()),
    }

    return render_template('settings.html',
                          client_count=client_count,
                          current_time=current_time,
                          db_size=db_size,
                          storage=storage,
                          retention=retention)


@app.route('/settings/save_retention', methods=['POST'])
@login_required
def save_retention():
    from gpu_report import save_runtime_settings, SETTING_BOUNDS
    updates = {}
    errors = []

    field_map = [
        ('gpu_hourly_days', 'retention_days', 'GPU 小时数据保留'),
        ('llm_report_count', 'llm_report_retention', 'LLM 周报保留'),
        ('uptime_days', 'uptime_record_retention_days', '可用性记录保留'),
    ]
    for form_key, cfg_key, label in field_map:
        raw = request.form.get(form_key)
        if raw is None or raw == '':
            continue
        try:
            n = int(raw)
        except ValueError:
            errors.append(f'{label} 不是合法整数')
            continue
        lo, hi = SETTING_BOUNDS[cfg_key]
        if not (lo <= n <= hi):
            errors.append(f'{label} 必须在 {lo} ~ {hi} 之间')
            continue
        updates[cfg_key] = n

    if errors:
        for e in errors:
            flash(e, 'danger')
    elif updates:
        save_runtime_settings(updates, app=app)
        flash(f'已保存:{", ".join(f"{k}={v}" for k, v in updates.items())}', 'success')
    else:
        flash('没有更新任何设置', 'info')
    return redirect(url_for('settings'))


@app.route('/settings/cleanup_gpu_hourly', methods=['POST'])
@login_required
def admin_cleanup_gpu_hourly():
    from gpu_report import cleanup_gpu_hourly_older_than
    try:
        days = int(request.form.get('older_than_days', 7))
    except ValueError:
        flash('参数不是合法整数', 'danger')
        return redirect(url_for('settings'))
    if days < 1 or days > 3650:
        flash('天数必须在 1 ~ 3650 之间', 'danger')
        return redirect(url_for('settings'))
    deleted = cleanup_gpu_hourly_older_than(days)
    flash(f'清理完成:删除 {deleted} 行 GPU 小时数据(早于 {days} 天前)', 'success')
    return redirect(url_for('settings'))


@app.route('/settings/cleanup_llm_reports', methods=['POST'])
@login_required
def admin_cleanup_llm_reports():
    from gpu_report import cleanup_llm_reports_keep
    try:
        keep = int(request.form.get('keep_latest_n', 12))
    except ValueError:
        flash('参数不是合法整数', 'danger')
        return redirect(url_for('settings'))
    if keep < 0 or keep > 1000:
        flash('保留条数必须在 0 ~ 1000 之间', 'danger')
        return redirect(url_for('settings'))
    deleted = cleanup_llm_reports_keep(keep)
    flash(f'清理完成:保留最近 {keep} 条 LLM 周报,删除 {deleted} 条', 'success')
    return redirect(url_for('settings'))


@app.route('/settings/cleanup_uptime', methods=['POST'])
@login_required
def admin_cleanup_uptime():
    from gpu_report import cleanup_uptime_older_than
    try:
        days = int(request.form.get('older_than_days', 90))
    except ValueError:
        flash('参数不是合法整数', 'danger')
        return redirect(url_for('settings'))
    if days < 7 or days > 3650:
        flash('天数必须在 7 ~ 3650 之间', 'danger')
        return redirect(url_for('settings'))
    deleted = cleanup_uptime_older_than(days)
    flash(f'清理完成:删除 {deleted} 行可用性记录(早于 {days} 天前)', 'success')
    return redirect(url_for('settings'))


@app.route('/settings/cleanup_log_backups', methods=['POST'])
@login_required
def admin_cleanup_log_backups():
    from gpu_report import cleanup_log_backups
    res = cleanup_log_backups()
    flash(f'清理完成:删除 {res["deleted_count"]} 个轮转日志文件,释放 '
          f'{res["bytes_freed"] / 1024:.1f} KB', 'success')
    return redirect(url_for('settings'))


@app.route('/settings/save_llm', methods=['POST'])
@login_required
def save_llm_settings():
    """保存 LLM 配置(provider / model / base_url / api_key / cron)。"""
    from gpu_report import save_runtime_settings
    updates = {}

    provider = request.form.get('llm_provider', '').strip()
    if provider in ('anthropic', 'openai'):
        updates['llm_provider'] = provider

    for field in ('llm_model', 'llm_base_url', 'llm_schedule_cron'):
        val = request.form.get(field, '').strip()
        if val:
            updates[field] = val

    # API key:仅在用户主动修改时才存(空提交表示"保持不变")
    api_key = request.form.get('llm_api_key', '').strip()
    if api_key:
        if api_key == '(env)':
            pass  # 占位符,用户没改,不更新
        else:
            updates['llm_api_key'] = api_key
    clear_key = request.form.get('clear_api_key')
    if clear_key:
        updates['llm_api_key'] = ''

    if updates:
        save_runtime_settings(updates, app=app)
        flash(f'LLM 配置已保存', 'success')
    else:
        flash('未检测到变化', 'info')
    return redirect(url_for('settings'))


@app.route('/settings/test_llm', methods=['POST'])
@login_required
def test_llm_connection():
    """测试 LLM API 连通性,返回 JSON。"""
    import time as _time
    from gpu_report.llm_agent import _build_llm_client, _call_llm
    from gpu_report.config import _get_cfg

    cfg = _get_cfg()
    # 允许前端临时覆盖(测试前填写但未保存)
    for field in ('llm_provider', 'llm_model', 'llm_base_url', 'llm_api_key'):
        val = request.json.get(field, '').strip() if request.is_json else ''
        if val and val != '(env)':
            cfg = {**cfg, field: val}

    sdk_client, err = _build_llm_client(cfg)
    if sdk_client is None:
        return jsonify({'ok': False, 'error': err}), 200

    t0 = _time.time()
    try:
        content, in_tok, out_tok = _call_llm(
            sdk_client, cfg,
            [{"role": "user", "content": "Reply with exactly: OK"}],
            max_tokens=20,
        )
        latency_ms = int((_time.time() - t0) * 1000)
        return jsonify({
            'ok': True,
            'model': cfg.get('llm_model'),
            'response': content.strip()[:80],
            'latency_ms': latency_ms,
            'input_tokens': in_tok,
            'output_tokens': out_tok,
        })
    except Exception as e:
        latency_ms = int((_time.time() - t0) * 1000)
        return jsonify({'ok': False, 'error': str(e), 'latency_ms': latency_ms})


@app.route('/settings/llm_models')
@login_required
def list_llm_models():
    """返回可用模型列表。Anthropic 用内置清单,OpenAI 兼容端点调 /v1/models。"""
    from gpu_report.llm_agent import _build_llm_client
    from gpu_report.config import _get_cfg, ANTHROPIC_KNOWN_MODELS

    cfg = _get_cfg()
    provider = cfg.get('llm_provider', 'anthropic')

    if provider == 'anthropic':
        return jsonify({'ok': True, 'models': ANTHROPIC_KNOWN_MODELS,
                        'source': 'built-in list'})

    # OpenAI-compatible: try /v1/models
    sdk_client, err = _build_llm_client(cfg)
    if sdk_client is None:
        return jsonify({'ok': False, 'error': err})
    try:
        resp = sdk_client.models.list()
        models = sorted([m.id for m in resp.data])
        return jsonify({'ok': True, 'models': models, 'source': 'api'})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@app.route('/settings/vacuum_db', methods=['POST'])
@login_required
def admin_vacuum_db():
    from gpu_report import vacuum_database
    res = vacuum_database()
    flash(f'VACUUM 完成:{res["before"] / 1024:.1f} KB → '
          f'{res["after"] / 1024:.1f} KB(回收 {res["freed"] / 1024:.1f} KB)',
          'success')
    return redirect(url_for('settings'))


# ─── 导出 / 导入 ──────────────────────────────────────────────────────────────

@app.route('/settings/export/db')
@login_required
def export_db():
    """整库 SQLite 文件下载,可用于异地备份/迁移。"""
    db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
    if not db_uri.startswith('sqlite:///'):
        flash('当前 DB 不是 SQLite,无法直接下载', 'danger')
        return redirect(url_for('settings'))
    db_path = db_uri.replace('sqlite:///', '')
    if not os.path.exists(db_path) or db_path == ':memory:':
        flash('数据库文件不存在或为内存模式', 'danger')
        return redirect(url_for('settings'))

    # 在导出前 commit 任何 pending 状态,确保磁盘文件最新
    db.session.commit()
    filename = f'omni-status-monitor-{datetime.now().strftime("%Y%m%d-%H%M%S")}.db'
    logger.info(f"管理员 {session.get('username')} 导出整库 → {filename}")
    return send_file(db_path, as_attachment=True, download_name=filename,
                     mimetype='application/octet-stream')


@app.route('/settings/export/gpu_hourly.csv')
@login_required
def export_gpu_hourly_csv():
    """GpuHourlyUsage 全量 CSV 导出,适合 pandas / Excel 分析。

    113 GPU × 168 小时 ≈ 19k 行,内存里凑成一个字符串就够,不需要 stream。
    """
    from gpu_report import GpuHourlyUsage
    import csv
    import io

    buf = io.StringIO()
    buf.write('﻿')  # UTF-8 BOM 让 Excel 不乱码
    w = csv.writer(buf)
    w.writerow(['client_id', 'gpu_index', 'hour', 'gpu_name',
                'vram_pct_avg', 'vram_pct_peak', 'util_pct_avg', 'util_pct_peak',
                'ok_sample_count', 'error_count'])
    rows = (GpuHourlyUsage.query
            .order_by(GpuHourlyUsage.client_id,
                      GpuHourlyUsage.gpu_index,
                      GpuHourlyUsage.hour)
            .all())
    for r in rows:
        w.writerow([r.client_id, r.gpu_index, r.hour.isoformat(),
                    r.gpu_name or '',
                    r.vram_pct_avg, r.vram_pct_peak,
                    r.util_pct_avg, r.util_pct_peak,
                    r.ok_sample_count, r.error_count])

    filename = f'gpu_hourly-{datetime.now().strftime("%Y%m%d-%H%M%S")}.csv'
    logger.info(f"管理员 {session.get('username')} 导出 {len(rows)} 行 GpuHourlyUsage")
    return Response(buf.getvalue(), mimetype='text/csv; charset=utf-8',
                    headers={'Content-Disposition':
                             f'attachment; filename="{filename}"'})


@app.route('/settings/export/llm_reports.json')
@login_required
def export_llm_reports():
    """所有 LlmReport 的 JSON 导出,可在被 cleanup 之前归档历史摘要。"""
    from gpu_report import LlmReport
    rows = LlmReport.query.order_by(LlmReport.generated_at.desc()).all()
    payload = [{
        'generated_at': r.generated_at.isoformat() if r.generated_at else None,
        'period_start': r.period_start.isoformat() if r.period_start else None,
        'period_end': r.period_end.isoformat() if r.period_end else None,
        'model': r.model, 'status': r.status, 'content': r.content,
        'input_tokens': r.input_tokens, 'output_tokens': r.output_tokens,
    } for r in rows]
    filename = f'llm_reports-{datetime.now().strftime("%Y%m%d-%H%M%S")}.json'
    body = json.dumps({'count': len(payload), 'reports': payload},
                      ensure_ascii=False, indent=2)
    logger.info(f"管理员 {session.get('username')} 导出 {len(payload)} 条 LLM 周报")
    return Response(body, mimetype='application/json; charset=utf-8',
                    headers={'Content-Disposition':
                             f'attachment; filename="{filename}"'})


@app.route('/settings/export/runtime_settings.json')
@login_required
def export_runtime_settings():
    from gpu_report import load_runtime_settings
    rs = load_runtime_settings()
    body = json.dumps(rs, ensure_ascii=False, indent=2)
    return Response(body, mimetype='application/json; charset=utf-8',
                    headers={'Content-Disposition':
                             'attachment; filename="runtime_settings.json"'})


@app.route('/settings/import/db', methods=['POST'])
@login_required
def import_db():
    """上传一个 SQLite 备份文件替换当前 DB。"""
    upload = request.files.get('db_file')
    if not upload or not upload.filename:
        flash('未选择要上传的文件', 'danger')
        return redirect(url_for('settings'))

    db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
    if not db_uri.startswith('sqlite:///'):
        flash('当前 DB 不是 SQLite,无法导入', 'danger')
        return redirect(url_for('settings'))
    db_path = db_uri.replace('sqlite:///', '')
    if db_path == ':memory:':
        flash('当前为内存模式,导入无意义', 'danger')
        return redirect(url_for('settings'))

    # Read first 16 bytes to verify SQLite magic
    head = upload.stream.read(16)
    if not head.startswith(b'SQLite format 3\x00'):
        flash('文件不是 SQLite 数据库(magic bytes 不匹配)', 'danger')
        return redirect(url_for('settings'))
    upload.stream.seek(0)

    backup_path = db_path + '.before-restore-' + datetime.now().strftime('%Y%m%d-%H%M%S')
    tmp_path = db_path + '.uploading'
    try:
        # 写入临时文件,完整后做原子替换
        with open(tmp_path, 'wb') as f:
            chunk_size = 1024 * 1024
            while True:
                chunk = upload.stream.read(chunk_size)
                if not chunk:
                    break
                f.write(chunk)

        # Sanity check: try to open uploaded file as SQLite and ensure required tables
        import sqlite3
        try:
            with sqlite3.connect(tmp_path) as conn:
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                names = {r[0] for r in cur.fetchall()}
        except sqlite3.DatabaseError as e:
            os.remove(tmp_path)
            flash(f'文件不是合法 SQLite 数据库:{e}', 'danger')
            return redirect(url_for('settings'))

        required = {'client', 'user'}
        if not required.issubset(names):
            os.remove(tmp_path)
            flash(f'数据库结构不匹配 omni-status(缺少表: {required - names})', 'danger')
            return redirect(url_for('settings'))

        # 关闭 SQLAlchemy 现有连接,以便能替换文件
        db.session.commit()
        db.engine.dispose()

        # 备份当前 DB,然后用上传的替换
        if os.path.exists(db_path):
            os.replace(db_path, backup_path)
        os.replace(tmp_path, db_path)
        # 触发 SQLAlchemy 在下次请求时重连
        db.engine.dispose()

        flash(f'数据库导入成功 · 旧库已备份为 {os.path.basename(backup_path)}', 'success')
        logger.info(f"管理员 {session.get('username')} 导入 DB,旧库备份 → {backup_path}")
    except Exception as e:
        # 失败时尝试回滚
        if os.path.exists(tmp_path):
            try: os.remove(tmp_path)
            except OSError: pass
        if os.path.exists(backup_path) and not os.path.exists(db_path):
            try: os.replace(backup_path, db_path)
            except OSError: pass
        flash(f'导入失败:{e}', 'danger')
        logger.error(f"DB 导入失败: {e}")

    return redirect(url_for('settings'))


@app.route('/settings/import/runtime_settings', methods=['POST'])
@login_required
def import_runtime_settings():
    """导入 runtime_settings.json,新值会经过相同的 bounds 校验。"""
    upload = request.files.get('settings_file')
    if not upload or not upload.filename:
        flash('未选择要上传的文件', 'danger')
        return redirect(url_for('settings'))

    try:
        data = json.loads(upload.stream.read().decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        flash(f'文件不是合法 JSON:{e}', 'danger')
        return redirect(url_for('settings'))
    if not isinstance(data, dict):
        flash('JSON 必须是对象 (key-value)', 'danger')
        return redirect(url_for('settings'))

    from gpu_report import save_runtime_settings, SETTING_BOUNDS
    valid = {}
    for k, v in data.items():
        if k in SETTING_BOUNDS:
            try:
                n = int(v)
            except (ValueError, TypeError):
                continue
            lo, hi = SETTING_BOUNDS[k]
            if lo <= n <= hi:
                valid[k] = n
    if not valid:
        flash('文件中没有可识别 / 合法的设置项', 'warning')
    else:
        save_runtime_settings(valid, app=app)
        flash(f'导入了 {len(valid)} 项设置:{", ".join(valid.keys())}', 'success')
    return redirect(url_for('settings'))


# 注册 GPU 报告 Blueprint(在所有模型定义之后)
from gpu_report import gpu_report_bp, load_gpu_report_config  # noqa: E402
app.register_blueprint(gpu_report_bp)

# 初始化 GPU 报告配置(自动 merge runtime_settings.json 的管理员覆盖)
app.config['GPU_REPORT'] = load_gpu_report_config()

if __name__ == '__main__':
    with app.app_context():
        init_db()  # 初始化数据库和创建管理员

    # APScheduler 只在真正的主进程中启动(避免 debug reloader 双起)
    if os.environ.get('WERKZEUG_RUN_MAIN') == 'true' or not config.get('debug', False):
        from gpu_report import init_scheduler
        init_scheduler(app)

    # 使用配置文件中的主机和端口
    app.run(host=config['host'], port=config['port'], debug=config['debug'])
