#!/usr/bin/env python3
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import functools
import json
import os
import logging
import configparser

# 配置日志
# 确保日志目录存在，如果无法创建系统日志目录则回退到本地目录
try:
    log_dir = '/var/log/system-monitor'
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, 'server.log')
except (PermissionError, OSError):
    # 如果无法创建系统日志目录，使用当前目录
    log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'server.log')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename=log_file
)
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
            existing_client = Client.query.get(config['id'])
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

# 配置Flask应用
app = Flask(__name__)
# 使用绝对路径存储数据库
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'monitor.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
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

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)  # 公告标题
    content = db.Column(db.Text, nullable=False)  # 公告内容
    created_at = db.Column(db.DateTime, default=datetime.now)  # 创建时间
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)  # 更新时间
    is_active = db.Column(db.Boolean, default=True)  # 是否启用
    priority = db.Column(db.Integer, default=0)  # 优先级，数值越大越靠前

# 实时数据存储（不持久化到数据库）
client_realtime_data = {}

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
    
    # 从配置文件加载客户端配置
    load_client_configs()

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
    
    # 存储实时数据（不持久化）
    client_realtime_data[data['client_id']] = {
        'timestamp': datetime.fromisoformat(data['timestamp']),
        'cpu': data['cpu'],
        'memory': data['memory'],
        'disks': data['disks'],
        'gpu': data['gpu'],
        'uptime_seconds': data['uptime_seconds']
    }
    
    db.session.commit()
    
    # 保存配置到文件（当有新客户端时自动保存）
    if client.id not in [c.id for c in Client.query.all()[:-1]]:
        save_client_configs()
    
    return jsonify({"status": "success"})

@app.route('/')
def dashboard():
    """主仪表盘页面"""
    clients = Client.query.order_by(Client.display_order).all()
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
                'gpu': realtime_data['gpu'],
                'uptime': uptime_str,
                'display_order': client.display_order
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
                'display_order': client.display_order
            })
    
    # 获取公告
    announcements = Announcement.query.filter_by(is_active=True).order_by(Announcement.priority.desc(), Announcement.created_at.desc()).all()
    
    return render_template('dashboard.html', clients=client_data, is_admin=session.get('logged_in', False), announcements=announcements)

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
        
        # 保存配置到文件
        save_client_configs()
        
        logger.info(f"Client information updated: {client.hostname} (ID: {client.id})")
        flash('客户端信息已更新', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('edit_client.html', client=client)

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
            announcement_id = request.form.get('announcement_id')
            announcement = Announcement.query.get(announcement_id)
            if announcement:
                announcement.is_active = not announcement.is_active
                db.session.commit()
                flash(f'公告已{"启用" if announcement.is_active else "禁用"}', 'success')
                
        elif action == 'delete':
            # 删除公告
            announcement_id = request.form.get('announcement_id')
            announcement = Announcement.query.get(announcement_id)
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
    
    # 获取数据库大小（简化版，因为移除了历史记录功能）
    db_size = None
    if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite'):
        db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
        try:
            db_size = os.path.getsize(db_path) / (1024 * 1024)  # MB
        except:
            pass
    
    return render_template('settings.html', 
                          client_count=client_count, 
                          current_time=current_time,
                          db_size=db_size)

if __name__ == '__main__':
    with app.app_context():
        init_db()  # 初始化数据库和创建管理员
    
    # 使用配置文件中的主机和端口
    app.run(host=config['host'], port=config['port'], debug=config['debug'])
