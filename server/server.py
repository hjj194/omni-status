#!/usr/bin/env python3
import sys
# 以 `python server.py` 启动时模块注册为 __main__，但 gpu_report/models.py 做
# `from server import db` 时找不到 server，触发循环 import。
# 提前将本模块注册为 'server'，让子包能安全地引用 db。
if __name__ == '__main__':
    sys.modules.setdefault('server', sys.modules['__main__'])

from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta, date as date_type
from werkzeug.security import generate_password_hash, check_password_hash
import functools
import hmac
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

def _idempotent_add_column(table: str, column_def: str):
    """对老库执行 ALTER TABLE ADD COLUMN,只忽略"列已存在"这一种错误。

    其它错误(磁盘满 / 表锁 / 库损坏)用 logger.error 暴露,
    避免 schema 升级失败被静默吞掉导致后续每次写入 NULL 列。
    """
    try:
        with db.engine.connect() as conn:
            conn.execute(db.text(f'ALTER TABLE {table} ADD COLUMN {column_def}'))
            conn.commit()
    except Exception as e:
        msg = str(e).lower()
        # SQLite: "duplicate column name: X"
        # Postgres: "column X of relation Y already exists"
        # MySQL: "Duplicate column name 'X'"
        is_duplicate = ('duplicate column' in msg
                        or 'already exists' in msg)
        if not is_duplicate:
            logger.error(
                f"ALTER TABLE {table} ADD COLUMN {column_def} 失败(非"
                f"重复列错误,需要排查 schema/磁盘/权限): {e}",
                exc_info=True)


# 创建数据库和初始管理员
def init_db():
    import gpu_report  # noqa: F401 — 触发 GpuHourlyUsage / LlmReport 模型注册
    db.create_all()

    # idempotent ALTER 给老库加新列。每条都独立 try,失败 log error 不中断启动
    # (希望尽量起来,即使部分列添加失败,db.create_all 已建好的新表仍可用)。
    _idempotent_add_column('client', 'display_order INTEGER DEFAULT 0')
    _idempotent_add_column('client', 'client_version VARCHAR(40)')
    _idempotent_add_column('user',   'must_change_password BOOLEAN DEFAULT 0')

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
    # hmac.compare_digest 是常量时间比较,避免内网 timing 推测 token 字符。
    expected_token = config.get('report_token', '')
    if expected_token:
        auth = request.headers.get('Authorization', '')
        token = (auth.removeprefix('Bearer ').strip()
                 if auth.startswith('Bearer ') else
                 request.headers.get('X-Report-Token', ''))
        if not token or not hmac.compare_digest(token, expected_token):
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

    # GPU 小时聚合(独立提交,失败不影响 dashboard)。
    # 用 error + exc_info: 这里失败意味着周报数据有洞,导师可能据此误判;
    # warning 在生产日志里太容易被忽略。
    try:
        from gpu_report import ingest_hourly_sample
        for gpu in data.get('gpu', []):
            ingest_hourly_sample(data['client_id'], gpu, now_ts)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(
            f"GPU 小时样本写入失败 client={data['client_id']}: {e}",
            exc_info=True)

    # 用户级 GPU 用量聚合(0511+ client 才上报 gpu_processes,老 client 跳过)
    if data.get('gpu_processes'):
        try:
            from gpu_report import ingest_user_hourly_sample
            for proc in data['gpu_processes']:
                ingest_user_hourly_sample(data['client_id'], proc, now_ts)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(
                f"用户级 GPU 样本写入失败 client={data['client_id']}: {e}",
                exc_info=True)

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

# reorder_clients、edit_client、delete_client、export_config、import_config、
# manage_announcements、edit_announcement 等管理路由已迁移到 admin_routes.py
# (模块末尾 import 触发注册)


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

    # 首次登录强制改密时只渲染最小密码修改页 —— 避免把完整设置布局/状态
    # 暴露给可能用默认凭据爆破进来的访客。POST 仍然走同一个 endpoint 处理改密。
    if session.get('must_change_password'):
        return render_template('force_password_change.html')

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


# /settings/save_retention、/settings/cleanup_*、/settings/save_llm、
# /settings/test_llm、/settings/llm_models、/settings/vacuum_db、
# /settings/export/*、/settings/import/* 已迁移到 settings_routes.py
# (在 server.py 末尾 import 时触发 @app.route 注册)




# 注册 GPU 报告 Blueprint(在所有模型定义之后)
from gpu_report import gpu_report_bp, load_gpu_report_config  # noqa: E402
app.register_blueprint(gpu_report_bp)

# 注册拆分出去的路由模块(import 即触发 @app.route 装饰器执行)
import admin_routes      # noqa: E402, F401
import settings_routes   # noqa: E402, F401

# 初始化 GPU 报告配置(自动 merge runtime_settings.json 的管理员覆盖)
app.config['GPU_REPORT'] = load_gpu_report_config()


def _bootstrap():
    """Idempotent 启动初始化:db + scheduler。

    设计目标:`python server.py` 和 `gunicorn server:app` 都能跑通。
    早期版本把这两步只放在 `if __name__ == '__main__'` 里,改成 gunicorn 部署
    会导致表不存在 + 周报/清理 job 永不运行,**且无明显报错**。

    幂等性:
    - init_db 内部用 db.create_all() 和 idempotent ALTER,重复调用无害
    - init_scheduler 模块级有 _scheduler is not None 短路

    Dev reloader 防双起:
    - werkzeug debug reloader 会在父进程 watch、子进程跑 app
    - 父进程没有 WERKZEUG_RUN_MAIN env var,我们跳过它的 scheduler init
    - 子进程有 WERKZEUG_RUN_MAIN=true,正常 init

    测试环境跳过:conftest.py 自己控制 init_db 时机,避免双 init。
    """
    if _is_testing:
        return

    is_dev_reloader_child = os.environ.get('WERKZEUG_RUN_MAIN') == 'true'
    is_dev_reloader_parent = config.get('debug', False) and not is_dev_reloader_child

    with app.app_context():
        init_db()

    if not is_dev_reloader_parent:
        from gpu_report import init_scheduler
        init_scheduler(app)

    # 多 worker 警告:dashboard 的 client_realtime_data 是进程内 dict,
    # gunicorn -w 2+ 会让每个 worker 看到不同数据。检测常见多 worker 标志。
    worker_count_envs = ('WEB_CONCURRENCY', 'GUNICORN_WORKERS')
    for env in worker_count_envs:
        try:
            if int(os.environ.get(env, '1')) > 1:
                logger.error(
                    f"⚠ 检测到 {env}={os.environ[env]} (多 worker 部署)。"
                    " dashboard 的实时数据是进程内 dict,多 worker 下 dashboard "
                    "数据会在 worker 间分裂。请使用 -w 1 或迁移到 Redis 后再开多 worker。"
                )
        except (TypeError, ValueError):
            pass


# 模块加载时执行 — gunicorn server:app 会触发,python server.py 也会触发
_bootstrap()


if __name__ == '__main__':
    # 使用配置文件中的主机和端口
    app.run(host=config['host'], port=config['port'], debug=config['debug'])
