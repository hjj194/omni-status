#!/usr/bin/env python3
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSON
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import functools
import json
import os
import logging
import configparser
import sqlite3

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='/var/log/system-monitor/server.log'
)
logger = logging.getLogger('system_monitor_server')

# 获取配置
def load_config():
    config = configparser.ConfigParser()
    config_file = '/etc/system-monitor/server/server.conf'
    
    # 默认配置
    default_config = {
        'host': '0.0.0.0',
        'port': 5000,
        'secret_key': os.environ.get('SECRET_KEY', 'dev_key_change_in_production'),
        'debug': False
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
                'debug': server_config.getboolean('debug')
            }
        except Exception as e:
            logger.error(f"加载配置文件失败: {e}")
    
    logger.warning("使用默认配置")
    return default_config

# 加载配置
config = load_config()

# 配置Flask应用
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///monitor.db'  # 使用SQLite简化部署
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = config['secret_key']  # 用于session
db = SQLAlchemy(app)

# 数据模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
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

class Metrics(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(36), db.ForeignKey('client.id'))
    timestamp = db.Column(db.DateTime, index=True)
    cpu_data = db.Column(JSON)  # CPU数据
    memory_data = db.Column(JSON)  # 内存数据
    disk_data = db.Column(JSON)  # 磁盘数据
    gpu_data = db.Column(JSON)  # GPU数据
    uptime_seconds = db.Column(db.Float)  # 运行时间(秒)

    client = db.relationship('Client', backref=db.backref('metrics', lazy='dynamic'))

# 创建数据库和初始管理员
def init_db():
    db.create_all()
    
    # 添加display_order列（如果是旧数据库更新）
    try:
        with app.app_context():
            db.engine.execute('ALTER TABLE client ADD COLUMN display_order INTEGER DEFAULT 0')
    except:
        pass  # 如果列已存在则忽略错误
    
    # 创建默认管理员账户
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin')
        admin.set_password('admin')  # 默认密码，生产环境中应修改
        db.session.add(admin)
        db.session.commit()
        logger.info("Created default admin user")

# 装饰器：需要登录
def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/report', methods=['POST'])
def report():
    """接收客户端上报的数据"""
    data = request.json
    
    # 获取或创建客户端记录
    client = Client.query.get(data['client_id'])
    if client is None:
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
    
    # 创建新的指标记录
    metrics = Metrics(
        client_id=data['client_id'],
        timestamp=datetime.fromisoformat(data['timestamp']),
        cpu_data=data['cpu'],
        memory_data=data['memory'],
        disk_data=data['disks'],
        gpu_data=data['gpu'],
        uptime_seconds=data['uptime_seconds']
    )
    db.session.add(metrics)
    
    # 清理旧数据 (保留30天)
    old_data_cutoff = datetime.now() - timedelta(days=30)
    old_metrics = Metrics.query.filter(Metrics.timestamp < old_data_cutoff).all()
    for old_metric in old_metrics:
        db.session.delete(old_metric)
    
    db.session.commit()
    return jsonify({"status": "success"})

@app.route('/')
def dashboard():
    """主仪表盘页面"""
    clients = Client.query.order_by(Client.display_order).all()
    client_data = []
    
    for client in clients:
        # 获取最新的指标数据
        latest_metrics = client.metrics.order_by(Metrics.timestamp.desc()).first()
        
        if latest_metrics:
            # 计算正常运行时间的格式化字符串
            uptime = timedelta(seconds=latest_metrics.uptime_seconds)
            days = uptime.days
            hours, remainder = divmod(uptime.seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            uptime_str = f"{days}天 {hours}小时 {minutes}分钟"
            
            # 检查是否最近报告过 (10分钟内)
            is_online = (datetime.now() - client.last_seen).total_seconds() < 600
            
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
            
            for disk in latest_metrics.disk_data:
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
                'cpu': latest_metrics.cpu_data,
                'memory': latest_metrics.memory_data,
                'disks': filtered_disks,
                'gpu': latest_metrics.gpu_data,
                'uptime': uptime_str,
                'display_order': client.display_order
            })
    
    return render_template('dashboard.html', clients=client_data, is_admin=session.get('logged_in', False))

@app.route('/reorder', methods=['GET', 'POST'])
@login_required
def reorder_clients():
    """重新排序客户端卡片"""
    if request.method == 'POST':
        # 获取新顺序
        client_ids = request.form.getlist('client_ids[]')
        
        # 更新数据库中的顺序
        for i, client_id in enumerate(client_ids):
            client = Client.query.get(client_id)
            if client:
                client.display_order = i
        
        db.session.commit()
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
            logger.info(f"Admin login successful: {username}")
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
        logger.info(f"Client information updated: {client.hostname} (ID: {client.id})")
        flash('客户端信息已更新', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('edit_client.html', client=client)

@app.route('/client/<client_id>/history')
def client_history(client_id):
    """查看客户端历史数据页面"""
    client = Client.query.get_or_404(client_id)
    period = request.args.get('period', 'week')  # 默认显示一周
    
    # 根据时间段过滤数据
    if period == 'week':
        cutoff = datetime.now() - timedelta(days=7)
    elif period == 'month':
        cutoff = datetime.now() - timedelta(days=30)
    elif period == 'halfyear':
        cutoff = datetime.now() - timedelta(days=182)
    elif period == 'year':
        cutoff = datetime.now() - timedelta(days=365)
    else:
        cutoff = datetime.now() - timedelta(days=7)  # 默认一周
    
    metrics = client.metrics.filter(Metrics.timestamp >= cutoff).order_by(Metrics.timestamp).all()
    
    # 准备图表数据
    timestamps = [m.timestamp.strftime('%Y-%m-%d %H:%M') for m in metrics]
    cpu_data = [m.cpu_data['usage_percent'] for m in metrics]
    memory_data = [m.memory_data['percent'] for m in metrics]
    
    # GPU数据可能不存在
    gpu_data = []
    for m in metrics:
        if m.gpu_data and len(m.gpu_data) > 0:
            gpu_data.append([gpu['utilization'] for gpu in m.gpu_data])
        else:
            gpu_data.append([])
    
    # 只提取根目录和总存储的磁盘数据
    disk_data = {}
    if metrics and metrics[0].disk_data:
        for m in metrics:
            # 找出根目录
            root_disk = next((d for d in m.disk_data if d['mountpoint'] == '/'), None)
            if root_disk:
                if '/' not in disk_data:
                    disk_data['/'] = []
                disk_data['/'].append(root_disk['percent'])
        
            # 计算总存储
            total_used = sum(d['used'] for d in m.disk_data)
            total_space = sum(d['total'] for d in m.disk_data)
            if total_space > 0:
                total_percent = (total_used / total_space) * 100
                if 'Total' not in disk_data:
                    disk_data['Total'] = []
                disk_data['Total'].append(total_percent)
    
    # 转换为JSON格式
    disk_data_json = {}
    for key, values in disk_data.items():
        disk_data_json[key] = values
    
    return render_template(
        'client_history.html',
        client=client,
        period=period,
        timestamps=json.dumps(timestamps),
        cpu_data=json.dumps(cpu_data),
        memory_data=json.dumps(memory_data),
        gpu_data=json.dumps(gpu_data),
        disk_data=json.dumps(disk_data_json),
        is_admin=session.get('logged_in', False)
    )

@app.route('/purge_data', methods=['POST'])
@login_required
def purge_data():
    """清除系统数据"""
    purge_type = request.form.get('purge_type')
    client_id = request.form.get('client_id')
    retention_days = request.form.get('retention_days')
    
    if purge_type == 'specific_client' and client_id:
        # 清除特定客户端的所有指标数据
        metrics_count = Metrics.query.filter_by(client_id=client_id).count()
        Metrics.query.filter_by(client_id=client_id).delete()
        db.session.commit()
        
        client = Client.query.get(client_id)
        client_name = client.display_name or client.hostname if client else "未知客户端"
        
        flash(f'已清除客户端"{client_name}"的所有监控数据，共{metrics_count}条记录', 'success')
        logger.info(f"Purged all metrics data for client {client_name} (ID: {client_id}), {metrics_count} records removed")
        
    elif purge_type == 'all_metrics':
        # 清除所有客户端的指标数据，但保留客户端信息
        metrics_count = Metrics.query.count()
        Metrics.query.delete()
        db.session.commit()
        flash(f'已清除所有监控数据，共{metrics_count}条记录', 'warning')
        logger.warning(f"Admin {session['username']} purged ALL metrics data, {metrics_count} records removed")
        
    elif purge_type == 'set_retention' and retention_days:
        # 根据设定的保留天数清除数据
        try:
            days = int(retention_days)
            if days < 1:
                flash('保留天数必须大于等于1', 'danger')
                return redirect(url_for('settings'))
                
            cutoff_date = datetime.now() - timedelta(days=days)
            count_before = Metrics.query.count()
            Metrics.query.filter(Metrics.timestamp < cutoff_date).delete()
            count_after = Metrics.query.count()
            deleted_count = count_before - count_after
            
            db.session.commit()
            flash(f'已清除{days}天之前的所有数据，共删除{deleted_count}条记录', 'success')
            logger.info(f"Purged metrics older than {days} days, {deleted_count} records removed")
        except ValueError:
            flash('请输入有效的天数', 'danger')
    
    return redirect(url_for('settings'))

@app.route('/optimize_database', methods=['POST'])
@login_required
def optimize_database():
    """优化SQLite数据库"""
    try:
        # 获取数据库文件路径
        db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
        
        # 确保数据库路径有效
        if not os.path.exists(db_path):
            flash('数据库文件不存在', 'danger')
            return redirect(url_for('settings'))
        
        # 获取优化前的大小
        size_before = os.path.getsize(db_path) / (1024 * 1024)  # MB
        
        # 连接数据库并执行VACUUM
        conn = sqlite3.connect(db_path)
        conn.execute('VACUUM')
        conn.close()
        
        # 获取优化后的大小
        size_after = os.path.getsize(db_path) / (1024 * 1024)  # MB
        saved = size_before - size_after
        
        flash(f'数据库优化完成。优化前: {size_before:.2f} MB, 优化后: {size_after:.2f} MB, 节省: {saved:.2f} MB', 'success')
        logger.info(f"Database optimized by admin {session['username']}, saved {saved:.2f} MB")
    except Exception as e:
        flash(f'数据库优化失败: {str(e)}', 'danger')
        logger.error(f"Database optimization failed: {str(e)}")
    
    return redirect(url_for('settings'))

@app.route('/system_status')
@login_required
def system_status():
    """系统状态信息"""
    # 获取数据库统计信息
    metrics_count = Metrics.query.count()
    client_count = Client.query.count()
    
    # 计算每个客户端的数据点数量
    client_data_counts = db.session.query(
        Metrics.client_id, 
        db.func.count(Metrics.id).label('count')
    ).group_by(Metrics.client_id).all()
    
    # 获取客户端信息
    client_stats = []
    for client_id, count in client_data_counts:
        client = Client.query.get(client_id)
        if client:
            client_stats.append({
                'id': client.id,
                'hostname': client.hostname,
                'display_name': client.display_name or client.hostname,
                'data_points': count,
                'last_seen': client.last_seen
            })
    
    # 估算数据库大小（如果使用SQLite）
    db_size = None
    if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite'):
        db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
        try:
            db_size = os.path.getsize(db_path) / (1024 * 1024)  # MB
        except:
            pass
    
    return render_template('system_status.html', 
                          metrics_count=metrics_count,
                          client_count=client_count,
                          client_stats=client_stats,
                          db_size=db_size)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """系统设置页面"""
    if request.method == 'POST':
        # 处理密码修改
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if new_password != confirm_password:
            flash('新密码和确认密码不匹配', 'danger')
            return redirect(url_for('settings'))
            
        user = User.query.filter_by(username=session['username']).first()
        if user and user.check_password(current_password):
            user.set_password(new_password)
            db.session.commit()
            flash('密码已成功更新', 'success')
            logger.info(f"Password changed for user: {user.username}")
        else:
            flash('当前密码不正确', 'danger')
        
        return redirect(url_for('settings'))
    
    # 获取客户端数量
    client_count = Client.query.count()
    
    # 获取当前时间
    current_time = datetime.now()
    
    # 获取数据库大小和指标数量
    db_size = None
    if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite'):
        db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
        try:
            db_size = os.path.getsize(db_path) / (1024 * 1024)  # MB
        except:
            pass
    
    metrics_count = Metrics.query.count()
    
    # 获取所有客户端供数据清除选择
    clients = Client.query.all()
    
    return render_template('settings.html', 
                          client_count=client_count, 
                          current_time=current_time,
                          clients=clients,
                          db_size=db_size,
                          metrics_count=metrics_count)

if __name__ == '__main__':
    with app.app_context():
        init_db()  # 初始化数据库和创建管理员
    
    # 使用配置文件中的主机和端口
    app.run(host=config['host'], port=config['port'], debug=config['debug'])
