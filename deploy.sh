#!/bin/bash
# System Monitor - Deployment Script
# This script sets up both server and client components as systemd services

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored section headers
print_section() {
    echo -e "\n${BLUE}=== $1 ===${NC}\n"
}

# Function to print success messages
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

# Function to print error messages
print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Function to print warning/info messages
print_warning() {
    echo -e "${YELLOW}! $1${NC}"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to identify the Linux distribution
identify_distro() {
    if command_exists apt-get; then
        echo "debian"
    elif command_exists yum; then
        echo "rhel"
    else
        echo "unknown"
    fi
}

# Function to install required packages
install_dependencies() {
    print_section "Installing Dependencies"
    
    local distro=$(identify_distro)
    
    if [ "$distro" = "debian" ]; then
        echo "Detected Debian/Ubuntu based system"
        sudo apt-get update
        sudo apt-get install -y python3 python3-pip python3-venv sqlite3
    elif [ "$distro" = "rhel" ]; then
        echo "Detected RHEL/CentOS based system"
        sudo yum -y update
        sudo yum -y install python3 python3-pip sqlite3
    else
        print_error "Unsupported Linux distribution. Please install the following packages manually:"
        echo "- python3"
        echo "- python3-pip"
        echo "- sqlite3"
        exit 1
    fi
    
    print_success "System dependencies installed"
}

# Function to create directories
create_directories() {
    print_section "Creating Directories"
    
    # Create directory for the application
    sudo mkdir -p /opt/system-monitor/server
    sudo mkdir -p /opt/system-monitor/client
    
    # Create directory for logs
    sudo mkdir -p /var/log/system-monitor
    
    # Set permissions
    sudo chown -R $USER:$USER /opt/system-monitor
    sudo chmod -R 755 /opt/system-monitor
    
    print_success "Directories created"
}

# Function to set up the virtual environment
setup_venv() {
    local component=$1
    print_section "Setting up Python virtual environment for $component"
    
    cd /opt/system-monitor/$component
    python3 -m venv venv
    source venv/bin/activate
    
    if [ "$component" = "server" ]; then
        pip install flask flask-sqlalchemy werkzeug
    else
        pip install psutil requests
    fi
    
    deactivate
    print_success "Virtual environment for $component configured"
}

# Function to create the server files
create_server_files() {
    print_section "Creating server files"
    
    # Create server.py
    cat > /opt/system-monitor/server/server.py << 'EOF'
#!/usr/bin/env python3
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSON
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import functools
import json
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///monitor.db'  # 使用SQLite简化部署
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_key_change_in_production')  # 用于session
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
        print("Created default admin user")

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
    clients = Client.query.all()
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
    clients = Client.query.all()
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
            return redirect(url_for('dashboard'))
        else:
            error = '用户名或密码错误'
    
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    """登出"""
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
        client.physical_address = request.form.get('physical_address')
        client.notes = request.form.get('notes')
        db.session.commit()
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

if __name__ == '__main__':
    with app.app_context():
        init_db()  # 初始化数据库和创建管理员
    app.run(host='0.0.0.0', port=5000, debug=False)
EOF

    # Create templates directory
    mkdir -p /opt/system-monitor/server/templates
    
    # Create dashboard.html
    cat > /opt/system-monitor/server/templates/dashboard.html << 'EOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>系统监控仪表盘</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css">
    <style>
        body {
            background-color: #f8f9fa;
        }
        .card {
            margin-bottom: 20px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            border-radius: 12px;
            transition: all 0.3s ease;
            border: none;
        }
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.15);
        }
        .compact-card {
            min-height: 280px;
        }
        .status-dot {
            height: 12px;
            width: 12px;
            border-radius: 50%;
            display: inline-block;
            margin-right: 5px;
        }
        .online {
            background-color: #28a745;
        }
        .offline {
            background-color: #dc3545;
        }
        .progress {
            height: 10px;
            margin-bottom: 10px;
            border-radius: 5px;
            background-color: rgba(0, 0, 0, 0.05);
        }
        .progress-bar {
            border-radius: 5px;
        }
        .metric-label {
            display: flex;
            justify-content: space-between;
            margin-bottom: 5px;
            font-size: 14px;
        }
        .metric-value {
            font-weight: 600;
        }
        .card-header {
            border-radius: 12px 12px 0 0 !important;
            background-color: #fff;
            border-bottom: 1px solid rgba(0, 0, 0, 0.05);
            padding: 15px 20px;
        }
        .card-body {
            padding: 20px;
        }
        .server-info {
            cursor: pointer;
        }
        .server-details {
            display: none;
            padding-top: 15px;
            margin-top: 15px;
            border-top: 1px solid rgba(0, 0, 0, 0.05);
        }
        .navbar {
            margin-bottom: 25px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        .badge {
            font-weight: 500;
            padding: 5px 10px;
            border-radius: 12px;
        }
        .ghost-card {
            border: 2px dashed #dee2e6;
            background-color: #f8f9fa;
            opacity: 0.7;
        }
        .handle {
            cursor: move;
            color: #6c757d;
        }
        .metric-icon {
            margin-right: 8px;
            color: #6c757d;
        }
        .client-card {
            transition: background-color 0.3s;
        }
        .client-card.dragging {
            background-color: #e9ecef;
            opacity: 0.7;
        }
        .tools-container {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        @media (max-width: 768px) {
            .card-header h5 {
                font-size: 1rem;
            }
            .card-body {
                padding: 15px;
            }
            .btn-sm {
                padding: .25rem .5rem;
                font-size: .75rem;
            }
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/">
                <i class="bi bi-pc-display"></i> 系统监控仪表盘
            </a>
            <div class="d-flex">
                <span class="navbar-text me-3 d-none d-sm-inline">
                    当前监控 {{ clients|length }} 台主机
                </span>
                {% if is_admin %}
                <div class="btn-group">
                    <a href="{{ url_for('reorder_clients') }}" class="btn btn-sm btn-outline-light" title="调整顺序">
                        <i class="bi bi-arrow-down-up"></i>
                        <span class="d-none d-md-inline ms-1">排序</span>
                    </a>
                    <a href="{{ url_for('logout') }}" class="btn btn-sm btn-outline-light" title="登出">
                        <i class="bi bi-box-arrow-right"></i>
                        <span class="d-none d-md-inline ms-1">登出</span>
                    </a>
                </div>
                {% else %}
                <a href="{{ url_for('login') }}" class="btn btn-sm btn-outline-light">
                    <i class="bi bi-box-arrow-in-right"></i>
                    <span class="d-none d-md-inline ms-1">管理员登录</span>
                </a>
                {% endif %}
            </div>
        </div>
    </nav>

    <div class="container">
        {% if not clients %}
        <div class="alert alert-info text-center">
            <h4>当前没有连接的客户端</h4>
            <p>请在客户端机器上启动监控脚本</p>
        </div>
        {% else %}
        <div class="row" id="client-cards-container">
            {% for client in clients|sort(attribute='display_order') %}
            <div class="col-lg-4 col-md-6 mb-4" data-client-id="{{ client.id }}">
                <div class="card compact-card client-card">
                    <!-- 基本信息卡片头部 -->
                    <div class="card-header d-flex justify-content-between align-items-center server-info" data-bs-toggle="collapse" data-bs-target="#serverDetails-{{ client.id }}" aria-expanded="false">
                        <h5 class="mb-0 d-flex align-items-center">
                            <span class="status-dot {% if client.is_online %}online{% else %}offline{% endif %}" title="{{ client.is_online and '在线' or '离线' }}"></span>
                            <span class="text-truncate">{{ client.display_name }}</span>
                        </h5>
                        <div class="tools-container">
                            {% if is_admin %}
                            <a href="{{ url_for('edit_client', client_id=client.id) }}" class="btn btn-sm btn-outline-primary" onclick="event.stopPropagation();" title="编辑客户端">
                                <i class="bi bi-pencil"></i>
                            </a>
                            {% endif %}
                            <i class="bi bi-chevron-down"></i>
                        </div>
                    </div>
                    
                    <!-- 基本信息内容 - 紧凑卡片 -->
                    <div class="card-body">
                        <div class="basic-info">
                            <div class="d-flex justify-content-between small mb-3">
                                <span class="badge bg-light text-dark">
                                    <i class="bi bi-geo-alt"></i> {{ client.physical_address }}
                                </span>
                                <span class="badge bg-light text-dark">
                                    <i class="bi bi-ethernet"></i> {{ client.ip_address }}
                                </span>
                            </div>
                            
                            <!-- CPU 使用情况 -->
                            <div class="metric-label">
                                <span><i class="bi bi-cpu metric-icon"></i>CPU</span>
                                <span class="metric-value">{{ client.cpu.usage_percent }}%</span>
                            </div>
                            <div class="progress">
                                <div class="progress-bar bg-primary" role="progressbar" 
                                    style="width: {{ client.cpu.usage_percent }}%;" 
                                    aria-valuenow="{{ client.cpu.usage_percent }}" aria-valuemin="0" aria-valuemax="100">
                                </div>
                            </div>
                            
                            <!-- 内存使用情况 -->
                            <div class="metric-label mt-3">
                                <span><i class="bi bi-memory metric-icon"></i>内存</span>
                                <span class="metric-value">{{ client.memory.percent }}%</span>
                            </div>
                            <div class="progress">
                                <div class="progress-bar bg-success" role="progressbar" 
                                    style="width: {{ client.memory.percent }}%;" 
                                    aria-valuenow="{{ client.memory.percent }}" aria-valuemin="0" aria-valuemax="100">
                                </div>
                            </div>
                            
                            <!-- 存储使用情况 - 总计 -->
                            {% set total_disk = client.disks|selectattr('mountpoint', 'equalto', 'Total')|first %}
                            {% if total_disk %}
                            <div class="metric-label mt-3">
                                <span><i class="bi bi-hdd metric-icon"></i>存储</span>
                                <span class="metric-value">{{ total_disk.percent|round(1) }}%</span>
                            </div>
                            <div class="progress">
                                <div class="progress-bar bg-warning" role="progressbar" 
                                    style="width: {{ total_disk.percent }}%;" 
                                    aria-valuenow="{{ total_disk.percent }}" aria-valuemin="0" aria-valuemax="100">
                                </div>
                            </div>
                            {% endif %}
                            
                            <!-- GPU 使用情况 - 如果有 -->
                            {% if client.gpu %}
                            {% set avg_gpu_usage = (client.gpu|map(attribute='utilization')|sum / client.gpu|length)|round(1) %}
                            <div class="metric-label mt-3">
                                <span><i class="bi bi-gpu-card metric-icon"></i>GPU</span>
                                <span class="metric-value">{{ avg_gpu_usage }}%</span>
                            </div>
                            <div class="progress">
                                <div class="progress-bar bg-danger" role="progressbar" 
                                    style="width: {{ avg_gpu_usage }}%;" 
                                    aria-valuenow="{{ avg_gpu_usage }}" aria-valuemin="0" aria-valuemax="100">
                                </div>
                            </div>
                            {% endif %}
                        </div>
                        
                        <!-- 详细信息（可折叠） -->
                        <div class="collapse server-details" id="serverDetails-{{ client.id }}">
                            <div class="row mb-3">
                                <div class="col-6">
                                    <small class="text-muted">主机名</small>
                                    <div>{{ client.hostname }}</div>
                                </div>
                                <div class="col-6">
                                    <small class="text-muted">最后在线</small>
                                    <div>{{ client.last_seen.strftime('%Y-%m-%d %H:%M') }}</div>
                                </div>
                            </div>
                            
                            <div class="mb-3">
                                <small class="text-muted">运行时间</small>
                                <div>{{ client.uptime }}</div>
                            </div>
                            
                            {% if client.notes %}
                            <div class="mb-3">
                                <small class="text-muted">备注</small>
                                <div class="font-italic">{{ client.notes }}</div>
                            </div>
                            {% endif %}
                            
                            <div class="mb-3">
                                <small class="text-muted">内存详情</small>
                                <div>已用 {{ (client.memory.used / (1024**3))|round(2) }} GB / 总计 {{ (client.memory.total / (1024**3))|round(2) }} GB</div>
                            </div>
                            
                            <!-- 磁盘使用情况 - 详情 -->
                            <div class="mb-3">
                                <small class="text-muted">存储详情</small>
                                {% for disk in client.disks %}
                                <div class="mt-2">
                                    <div class="small mb-1 d-flex justify-content-between">
                                        <span>{{ disk.mountpoint }}</span>
                                        <span>{{ disk.percent|round(1) }}%</span>
                                    </div>
                                    <div class="progress" style="height: 8px;">
                                        <div class="progress-bar bg-warning" role="progressbar" 
                                            style="width: {{ disk.percent }}%;" 
                                            aria-valuenow="{{ disk.percent }}" aria-valuemin="0" aria-valuemax="100">
                                        </div>
                                    </div>
                                    <div class="small text-muted">已用 {{ (disk.used / (1024**3))|round(2) }} GB / 总计 {{ (disk.total / (1024**3))|round(2) }} GB</div>
                                </div>
                                {% endfor %}
                            </div>
                            
                            <!-- GPU 使用情况 - 详情 -->
                            {% if client.gpu %}
                            <div class="mb-3">
                                <small class="text-muted">GPU详情</small>
                                {% for gpu in client.gpu %}
                                <div class="mt-2">
                                    <div class="small mb-1 d-flex justify-content-between">
                                        <span>{{ gpu.name }}</span>
                                        <span>{{ gpu.utilization|round(1) }}%</span>
                                    </div>
                                    <div class="progress" style="height: 8px;">
                                        <div class="progress-bar bg-danger" role="progressbar" 
                                            style="width: {{ gpu.utilization }}%;" 
                                            aria-valuenow="{{ gpu.utilization }}" aria-valuemin="0" aria-valuemax="100">
                                        </div>
                                    </div>
                                    <div class="small text-muted">GPU内存: {{ gpu.memory_used }} MB / {{ gpu.memory_total }} MB</div>
                                </div>
                                {% endfor %}
                            </div>
                            {% endif %}
                            
                            <!-- 历史数据链接 -->
                            <div class="mt-4">
                                <div class="btn-group btn-group-sm w-100">
                                    <a href="{{ url_for('client_history', client_id=client.id, period='week') }}" class="btn btn-outline-secondary">一周</a>
                                    <a href="{{ url_for('client_history', client_id=client.id, period='month') }}" class="btn btn-outline-secondary">一月</a>
                                    <a href="{{ url_for('client_history', client_id=client.id, period='halfyear') }}" class="btn btn-outline-secondary">半年</a>
                                    <a href="{{ url_for('client_history', client_id=client.id, period='year') }}" class="btn btn-outline-secondary">一年</a>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            {% endfor %}
        </div>
        {% endif %}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // 初始化可折叠面板
        document.addEventListener('DOMContentLoaded', function() {
            const serverInfoElements = document.querySelectorAll('.server-info');
            
            serverInfoElements.forEach(function(element) {
                element.addEventListener('click', function() {
                    // 获取箭头图标
                    const icon = this.querySelector('.bi-chevron-down, .bi-chevron-up');
                    // 切换箭头方向
                    if (icon.classList.contains('bi-chevron-down')) {
                        icon.classList.remove('bi-chevron-down');
                        icon.classList.add('bi-chevron-up');
                    } else {
                        icon.classList.remove('bi-chevron-up');
                        icon.classList.add('bi-chevron-down');
                    }
                    
                    // 获取详细信息区域
                    const targetId = this.getAttribute('data-bs-target');
                    const detailsElement = document.querySelector(targetId);
                    
                    // 使用Bootstrap的collapse API
                    const bsCollapse = new bootstrap.Collapse(detailsElement, {
                        toggle: true
                    });
                });
            });
        });
    </script>
</body>
</html>
EOF

    # Create additional HTML templates
    # login.html
    cat > /opt/system-monitor/server/templates/login.html << 'EOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>管理员登录 - 系统监控仪表盘</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css">
    <style>
        body {
            background-color: #f5f5f5;
            height: 100vh;
            display: flex;
            align-items: center;
        }
        .login-container {
            max-width: 400px;
            padding: 15px;
            margin: auto;
        }
        .card {
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
        }
        .card-header {
            border-radius: 10px 10px 0 0 !important;
            background-color: #343a40;
            color: white;
        }
        .btn-primary {
            width: 100%;
            padding: 10px;
            margin-top: 15px;
        }
    </style>
</head>
<body>
    <div class="container login-container">
        <div class="text-center mb-4">
            <i class="bi bi-pc-display" style="font-size: 3rem;"></i>
            <h2 class="mt-2">系统监控仪表盘</h2>
            <p class="text-muted">管理员登录</p>
        </div>
        
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0 text-center">登录</h5>
            </div>
            <div class="card-body p-4">
                {% if error %}
                <div class="alert alert-danger" role="alert">
                    {{ error }}
                </div>
                {% endif %}
                
                <form method="post">
                    <div class="mb-3">
                        <label for="username" class="form-label">用户名</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="bi bi-person"></i></span>
                            <input type="text" class="form-control" id="username" name="username" required autofocus>
                        </div>
                    </div>
                    
                    <div class="mb-3">
                        <label for="password" class="form-label">密码</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="bi bi-key"></i></span>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">
                        <i class="bi bi-box-arrow-in-right me-2"></i>登录
                    </button>
                </form>
            </div>
        </div>
        
        <div class="text-center mt-3">
            <a href="/" class="text-decoration-none">
                <i class="bi bi-arrow-left"></i> 返回仪表盘
            </a>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
EOF

    # Edit Client
    cat > /opt/system-monitor/server/templates/edit_client.html << 'EOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>编辑客户端信息</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css">
    <style>
        .navbar {
            margin-bottom: 25px;
        }
        .card {
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/">
                <i class="bi bi-pc-display"></i> 系统监控仪表盘
            </a>
            <div>
                <a href="{{ url_for('logout') }}" class="btn btn-sm btn-outline-light">
                    <i class="bi bi-box-arrow-right"></i> 登出
                </a>
            </div>
        </div>
    </nav>

    <div class="container">
        {% if session.get('logged_in') %}
            <div class="row justify-content-center">
                <div class="col-md-8">
                    <div class="card">
                        <div class="card-header">
                            <h5 class="mb-0">编辑客户端信息</h5>
                        </div>
                        <div class="card-body">
                            <form method="post">
                                <div class="mb-3">
                                    <label for="hostname" class="form-label">主机名</label>
                                    <input type="text" class="form-control" id="hostname" value="{{ client.hostname }}" disabled>
                                    <div class="form-text">主机名由客户端上报，不可编辑</div>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="ip_address" class="form-label">IP地址</label>
                                    <input type="text" class="form-control" id="ip_address" value="{{ client.ip_address }}" disabled>
                                    <div class="form-text">IP地址由客户端上报，不可编辑</div>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="display_name" class="form-label">显示名称</label>
                                    <input type="text" class="form-control" id="display_name" name="display_name" value="{{ client.display_name or '' }}">
                                    <div class="form-text">这个名称将在仪表盘中显示，使用更易识别的名称</div>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="physical_address" class="form-label">物理地址</label>
                                    <input type="text" class="form-control" id="physical_address" name="physical_address" value="{{ client.physical_address or '' }}">
                                    <div class="form-text">设备的物理位置（如：数据中心A, 3号机房机柜5）</div>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="notes" class="form-label">备注信息</label>
                                    <textarea class="form-control" id="notes" name="notes" rows="4">{{ client.notes or '' }}</textarea>
                                    <div class="form-text">关于这台机器的其他重要信息</div>
                                </div>
                                
                                <div class="d-flex justify-content-end">
                                    <a href="{{ url_for('dashboard') }}" class="btn btn-secondary me-2">取消</a>
                                    <button type="submit" class="btn btn-primary">保存</button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        {% else %}
            <div class="alert alert-danger text-center">
                <h4>无权限访问</h4>
                <p>您需要以管理员身份登录才能编辑客户端信息</p>
                <a href="{{ url_for('login') }}" class="btn btn-primary mt-3">登录</a>
                <a href="{{ url_for('dashboard') }}" class="btn btn-secondary mt-3 ms-2">返回仪表盘</a>
            </div>
        {% endif %}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
EOF

    # Reorder clients template
    cat > /opt/system-monitor/server/templates/reorder_clients.html << 'EOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>调整客户端顺序 - 系统监控仪表盘</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css">
    <style>
        body {
            background-color: #f8f9fa;
        }
        .navbar {
            margin-bottom: 25px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        .card {
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            border-radius: 10px;
            margin-bottom: 15px;
            border: none;
            background-color: #fff;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }
        .card-header {
            border-radius: 10px 10px 0 0 !important;
            background-color: #fff;
            border-bottom: 1px solid rgba(0, 0, 0, 0.05);
        }
        .sortable-item {
            cursor: move;
        }
        .sortable-ghost {
            opacity: 0.4;
            background-color: #e9ecef;
        }
        .sortable-chosen {
            background-color: #f8f9fa;
            box-shadow: 0 0 15px rgba(0, 0, 0, 0.1);
        }
        .sortable-drag {
            border: 2px dashed #6c757d;
        }
        .handle {
            cursor: move;
            color: #6c757d;
            margin-right: 10px;
            font-size: 1.2rem;
        }
        .status-dot {
            height: 10px;
            width: 10px;
            border-radius: 50%;
            display: inline-block;
            margin-right: 5px;
        }
        .online {
            background-color: #28a745;
        }
        .offline {
            background-color: #dc3545;
        }
        .client-info {
            flex-grow: 1;
            margin-left: 10px;
            overflow: hidden;
        }
        .client-name {
            font-weight: 600;
            max-width: 180px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .client-meta {
            font-size: 0.85rem;
            color: #6c757d;
            display: flex;
            gap: 15px;
        }
        .instructions {
            background-color: #fff;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 25px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }
        @media (max-width: 768px) {
            .client-meta {
                flex-direction: column;
                gap: 5px;
            }
            .client-name {
                max-width: 120px;
            }
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/">
                <i class="bi bi-pc-display"></i> 系统监控仪表盘
            </a>
            <div class="d-flex">
                <a href="{{ url_for('dashboard') }}" class="btn btn-sm btn-outline-light me-2">
                    <i class="bi bi-arrow-left"></i> 返回仪表盘
                </a>
                <a href="{{ url_for('logout') }}" class="btn btn-sm btn-outline-light">
                    <i class="bi bi-box-arrow-right"></i> 登出
                </a>
            </div>
        </div>
    </nav>

    <div class="container">
        <div class="instructions">
            <h4 class="mb-3"><i class="bi bi-arrow-down-up"></i> 调整客户端显示顺序</h4>
            <p>拖拽客户端卡片可以调整其在仪表盘上的显示顺序。调整完成后，点击"保存顺序"按钮使更改生效。</p>
            <div class="d-flex align-items-center">
                <i class="bi bi-info-circle me-2 text-primary"></i>
                <span>提示：您还可以通过拖拽客户端左侧的 <i class="bi bi-grip-vertical"></i> 图标来调整顺序</span>
            </div>
        </div>

        {% if not clients %}
        <div class="alert alert-info text-center">
            <h4>当前没有连接的客户端</h4>
            <p>请在客户端机器上启动监控脚本</p>
        </div>
        {% else %}
        <form id="reorderForm" method="post">
            <div class="row mb-4">
                <div class="col-12">
                    <div id="clientList" class="list-group">
                        {% for client in clients|sort(attribute='display_order') %}
                        <div class="card sortable-item" data-id="{{ client.id }}">
                            <div class="card-body d-flex align-items-center">
                                <input type="hidden" name="client_ids[]" value="{{ client.id }}">
                                <i class="bi bi-grip-vertical handle"></i>
                                <div class="d-flex align-items-center client-info">
                                    <span class="status-dot {% if client.is_online %}online{% else %}offline{% endif %}"></span>
                                    <div>
                                        <div class="client-name">{{ client.display_name }}</div>
                                        <div class="client-meta">
                                            <span><i class="bi bi-ethernet"></i> {{ client.ip_address }}</span>
                                            <span><i class="bi bi-geo-alt"></i> {{ client.physical_address }}</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </div>
            
            <div class="row">
                <div class="col-12 text-center">
                    <button type="submit" class="btn btn-primary btn-lg">
                        <i class="bi bi-check-lg"></i> 保存顺序
                    </button>
                </div>
            </div>
        </form>
        {% endif %}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/sortablejs@1.14.0/Sortable.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const clientList = document.getElementById('clientList');
            if (clientList) {
                new Sortable(clientList, {
                    animation: 150,
                    handle: '.handle',
                    ghostClass: 'sortable-ghost',
                    chosenClass: 'sortable-chosen',
                    dragClass: 'sortable-drag',
                    onEnd: function(evt) {
                        // 更新隐藏输入字段的顺序，保持与DOM顺序一致
                        const inputs = clientList.querySelectorAll('input[name="client_ids[]"]');
                        const items = clientList.querySelectorAll('.sortable-item');
                        
                        items.forEach((item, index) => {
                            const clientId = item.dataset.id;
                            inputs[index].value = clientId;
                        });
                    }
                });
            }
        });
    </script>
</body>
</html>
EOF

    # Client History
    cat > /opt/system-monitor/server/templates/client_history.html << 'EOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ client.display_name }} - 历史数据</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.7.1/dist/chart.min.js"></script>
    <style>
        body {
            background-color: #f8f9fa;
        }
        .navbar {
            margin-bottom: 25px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        .card {
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
            border-radius: 12px;
            border: none;
        }
        .card-header {
            border-radius: 12px 12px 0 0 !important;
            background-color: #fff;
            border-bottom: 1px solid rgba(0, 0, 0, 0.05);
            padding: 15px 20px;
        }
        .chart-container {
            min-height: 300px;
            margin-bottom: 20px;
            position: relative;
        }
        .card-body {
            padding: 20px;
        }
        .badge {
            font-weight: 500;
            padding: 5px 10px;
            border-radius: 12px;
        }
        .period-selector {
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            padding: 5px;
        }
        @media (max-width: 768px) {
            .period-selector .btn {
                padding: .25rem .5rem;
                font-size: .75rem;
            }
            .card-header h5 {
                font-size: 1rem;
            }
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/">
                <i class="bi bi-pc-display"></i> 系统监控仪表盘
            </a>
            <div class="d-flex">
                <a href="{{ url_for('dashboard') }}" class="btn btn-sm btn-outline-light me-2">
                    <i class="bi bi-arrow-left"></i> 
                    <span class="d-none d-md-inline">返回仪表盘</span>
                </a>
                {% if is_admin %}
                <a href="{{ url_for('logout') }}" class="btn btn-sm btn-outline-light">
                    <i class="bi bi-box-arrow-right"></i>
                    <span class="d-none d-md-inline">登出</span>
                </a>
                {% else %}
                <a href="{{ url_for('login') }}" class="btn btn-sm btn-outline-light">
                    <i class="bi bi-box-arrow-in-right"></i>
                    <span class="d-none d-md-inline">管理员登录</span>
                </a>
                {% endif %}
            </div>
        </div>
    </nav>

    <div class="container">
        <div class="row mb-4">
            <div class="col-12">
                <div class="d-flex justify-content-between align-items-center flex-wrap">
                    <h4 class="mb-3 mb-md-0">
                        <i class="bi bi-graph-up"></i> {{ client.display_name }} - 历史数据
                    </h4>
                    <div class="period-selector">
                        <div class="btn-group" role="group">
                            <a href="{{ url_for('client_history', client_id=client.id, period='week') }}" class="btn btn-sm btn-{% if period == 'week' %}primary{% else %}outline-primary{% endif %}">一周</a>
                            <a href="{{ url_for('client_history', client_id=client.id, period='month') }}" class="btn btn-sm btn-{% if period == 'month' %}primary{% else %}outline-primary{% endif %}">一月</a>
                            <a href="{{ url_for('client_history', client_id=client.id, period='halfyear') }}" class="btn btn-sm btn-{% if period == 'halfyear' %}primary{% else %}outline-primary{% endif %}">半年</a>
                            <a href="{{ url_for('client_history', client_id=client.id, period='year') }}" class="btn btn-sm btn-{% if period == 'year' %}primary{% else %}outline-primary{% endif %}">一年</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="row mb-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-3 col-6 mb-3">
                                <div class="d-flex align-items-center">
                                    <i class="bi bi-pc-display me-2 text-primary" style="font-size: 1.5rem;"></i>
                                    <div>
                                        <div class="text-muted small">主机名</div>
                                        <div class="fw-bold">{{ client.hostname }}</div>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-3 col-6 mb-3">
                                <div class="d-flex align-items-center">
                                    <i class="bi bi-ethernet me-2 text-success" style="font-size: 1.5rem;"></i>
                                    <div>
                                        <div class="text-muted small">IP地址</div>
                                        <div class="fw-bold">{{ client.ip_address }}</div>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-3 col-6 mb-3">
                                <div class="d-flex align-items-center">
                                    <i class="bi bi-geo-alt me-2 text-warning" style="font-size: 1.5rem;"></i>
                                    <div>
                                        <div class="text-muted small">物理地址</div>
                                        <div class="fw-bold">{{ client.physical_address or '未设置' }}</div>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-3 col-6 mb-3">
                                <div class="d-flex align-items-center">
                                    <i class="bi bi-clock-history me-2 text-danger" style="font-size: 1.5rem;"></i>
                                    <div>
                                        <div class="text-muted small">最后在线</div>
                                        <div class="fw-bold">{{ client.last_seen.strftime('%Y-%m-%d %H:%M') }}</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row">
            <!-- CPU 历史 -->
            <div class="col-lg-6 col-md-12">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">
                            <i class="bi bi-cpu me-2 text-primary"></i>CPU 使用率历史
                        </h5>
                    </div>
                    <div class="card-body chart-container">
                        <canvas id="cpuChart"></canvas>
                    </div>
                </div>
            </div>
            
            <!-- 内存历史 -->
            <div class="col-lg-6 col-md-12">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">
                            <i class="bi bi-memory me-2 text-success"></i>内存使用率历史
                        </h5>
                    </div>
                    <div class="card-body chart-container">
                        <canvas id="memoryChart"></canvas>
                    </div>
                </div>
            </div>
            
            <!-- 磁盘历史 - 只显示根目录和总存储 -->
            <div class="col-lg-6 col-md-12 mt-4">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">
                            <i class="bi bi-hdd me-2 text-warning"></i>存储使用率历史
                        </h5>
                    </div>
                    <div class="card-body chart-container">
                        <canvas id="diskChart"></canvas>
                    </div>
                </div>
            </div>
            
            <!-- GPU 历史（如果有） -->
            {% if gpu_data and gpu_data != '[]' %}
            <div class="col-lg-6 col-md-12 mt-4">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">
                            <i class="bi bi-gpu-card me-2 text-danger"></i>GPU 使用率历史
                        </h5>
                    </div>
                    <div class="card-body chart-container">
                        <canvas id="gpuChart"></canvas>
                    </div>
                </div>
            </div>
            {% endif %}
        </div>
    </div>
    
    <script>
        // Chart.js 配置
        const commonOptions = {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top',
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    backgroundColor: 'rgba(255, 255, 255, 0.9)',
                    titleColor: '#212529',
                    bodyColor: '#212529',
                    borderColor: '#dee2e6',
                    borderWidth: 1,
                    padding: 10,
                    boxPadding: 6,
                    usePointStyle: true,
                    callbacks: {
                        label: function(context) {
                            return context.dataset.label + ': ' + context.raw.toFixed(1) + '%';
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    title: {
                        display: true,
                        text: '使用率 (%)'
                    },
                    grid: {
                        color: 'rgba(0, 0, 0, 0.05)'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: '时间'
                    },
                    grid: {
                        display: false
                    },
                    ticks: {
                        maxTicksLimit: 8,
                        maxRotation: 0
                    }
                }
            },
            elements: {
                line: {
                    tension: 0.3
                },
                point: {
                    radius: 0,
                    hoverRadius: 6,
                    hitRadius: 6
                }
            }
        };
        
        // 对较小屏幕进行响应式调整
        function adjustOptionsForMobile() {
            if (window.innerWidth < 768) {
                commonOptions.scales.x.ticks.maxTicksLimit = 5;
                commonOptions.plugins.legend.labels = { boxWidth: 10, padding: 5 };
            }
        }
        adjustOptionsForMobile();
        
        // 数据
        const timestamps = {{ timestamps|safe }};
        const cpuData = {{ cpu_data|safe }};
        const memoryData = {{ memory_data|safe }};
        const diskData = {{ disk_data|safe }};
        const gpuData = {{ gpu_data|safe }};
        
        // 截取数据以改善移动设备上的可读性
        function downSampleData(data, labels, maxPoints = 50) {
            if (data.length <= maxPoints) return { data, labels };
            
            const step = Math.ceil(data.length / maxPoints);
            const reducedData = [];
            const reducedLabels = [];
            
            for (let i = 0; i < data.length; i += step) {
                reducedData.push(data[i]);
                reducedLabels.push(labels[i]);
            }
            
            return { data: reducedData, labels: reducedLabels };
        }
        
        let processedData = { data: cpuData, labels: timestamps };
        if (window.innerWidth < 768) {
            processedData = downSampleData(cpuData, timestamps);
        }
        
        // CPU Chart
        const cpuCtx = document.getElementById('cpuChart').getContext('2d');
        new Chart(cpuCtx, {
            type: 'line',
            data: {
                labels: processedData.labels,
                datasets: [{
                    label: 'CPU 使用率',
                    data: processedData.data,
                    borderColor: 'rgba(54, 162, 235, 1)',
                    backgroundColor: 'rgba(54, 162, 235, 0.2)',
                    borderWidth: 2,
                    fill: true
                }]
            },
            options: commonOptions
        });
        
        // Memory Chart
        let processedMemoryData = { data: memoryData, labels: timestamps };
        if (window.innerWidth < 768) {
            processedMemoryData = downSampleData(memoryData, timestamps);
        }
        
        const memoryCtx = document.getElementById('memoryChart').getContext('2d');
        new Chart(memoryCtx, {
            type: 'line',
            data: {
                labels: processedMemoryData.labels,
                datasets: [{
                    label: '内存使用率',
                    data: processedMemoryData.data,
                    borderColor: 'rgba(75, 192, 192, 1)',
                    backgroundColor: 'rgba(75, 192, 192, 0.2)',
                    borderWidth: 2,
                    fill: true
                }]
            },
            options: commonOptions
        });
        
        // Disk Chart - 只显示根目录和总存储
        const diskCtx = document.getElementById('diskChart').getContext('2d');
        const diskDatasets = [];
        
        const colors = {
            '/': {
                border: 'rgba(255, 159, 64, 1)',
                background: 'rgba(255, 159, 64, 0.1)'
            },
            'Total': {
                border: 'rgba(153, 102, 255, 1)',
                background: 'rgba(153, 102, 255, 0.1)'
            }
        };
        
        for (const [mountpoint, data] of Object.entries(diskData)) {
            const color = colors[mountpoint] || {
                border: `rgba(${Math.floor(Math.random() * 255)}, ${Math.floor(Math.random() * 255)}, ${Math.floor(Math.random() * 255)}, 1)`,
                background: `rgba(${Math.floor(Math.random() * 255)}, ${Math.floor(Math.random() * 255)}, ${Math.floor(Math.random() * 255)}, 0.1)`
            };
            
            let processedDiskData = { data: data, labels: timestamps };
            if (window.innerWidth < 768) {
                processedDiskData = downSampleData(data, timestamps);
            }
            
            diskDatasets.push({
                label: mountpoint === '/' ? '根目录 (/)' : '总存储',
                data: processedDiskData.data,
                borderColor: color.border,
                backgroundColor: color.background,
                borderWidth: 2,
                fill: true
            });
        }
        
        new Chart(diskCtx, {
            type: 'line',
            data: {
                labels: window.innerWidth < 768 ? downSampleData(cpuData, timestamps).labels : timestamps,
                datasets: diskDatasets
            },
            options: commonOptions
        });
        
        // GPU Chart (如果有)
        if (gpuData && gpuData.length > 0 && gpuData[0].length > 0) {
            const gpuCtx = document.getElementById('gpuChart').getContext('2d');
            const gpuDatasets = [];
            
            // 转换GPU数据
            const numGPUs = gpuData[0].length;
            
            for (let i = 0; i < numGPUs; i++) {
                let dataForThisGPU = gpuData.map(timepoint => timepoint[i] || 0);
                let processedGpuData = { data: dataForThisGPU, labels: timestamps };
                
                if (window.innerWidth < 768) {
                    processedGpuData = downSampleData(dataForThisGPU, timestamps);
                }
                
                gpuDatasets.push({
                    label: `GPU ${i}`,
                    data: processedGpuData.data,
                    borderColor: `rgba(${50 + i * 70}, ${150 - i * 30}, ${255 - i * 50}, 1)`,
                    backgroundColor: `rgba(${50 + i * 70}, ${150 - i * 30}, ${255 - i * 50}, 0.1)`,
                    borderWidth: 2,
                    fill: true
                });
            }
            
            new Chart(gpuCtx, {
                type: 'line',
                data: {
                    labels: window.innerWidth < 768 ? downSampleData(cpuData, timestamps).labels : timestamps,
                    datasets: gpuDatasets
                },
                options: commonOptions
            });
        }
    </script>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
EOF
    
    print_success "Server files created"
    
    # Make server.py executable
    chmod +x /opt/system-monitor/server/server.py
}

# Function to create client file
create_client_file() {
    print_section "Creating client file"
    
    cat > /opt/system-monitor/client/client.py << 'EOF'
#!/usr/bin/env python3
import os
import time
import json
import socket
import platform
import psutil
import requests
import uuid
import logging
from datetime import datetime
import subprocess

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='/var/log/system-monitor/client.log'
)
logger = logging.getLogger('client_monitor')

# 配置
SERVER_URL = "http://SERVER_IP:5000/report"  # 由部署脚本替换为实际服务器地址
REPORT_INTERVAL = 60  # 数据上报间隔（秒）
CLIENT_ID_FILE = "/opt/system-monitor/client/.client_id"  # 存储客户端ID的文件

# 获取或创建客户端ID
def get_client_id():
    if os.path.exists(CLIENT_ID_FILE):
        with open(CLIENT_ID_FILE, 'r') as f:
            return f.read().strip()
    else:
        client_id = str(uuid.uuid4())
        with open(CLIENT_ID_FILE, 'w') as f:
            f.write(client_id)
        return client_id

CLIENT_ID = get_client_id()

def get_nvidia_gpu_info():
    """获取NVIDIA GPU信息"""
    try:
        result = subprocess.run(['nvidia-smi', '--query-gpu=name,utilization.gpu,memory.used,memory.total', 
                              '--format=csv,noheader,nounits'], 
                             capture_output=True, text=True, check=True)
        
        gpus = []
        for i, line in enumerate(result.stdout.strip().split('\n')):
            if line.strip():
                name, utilization, mem_used, mem_total = line.split(', ')
                gpus.append({
                    'index': i,
                    'name': name,
                    'utilization': float(utilization),
                    'memory_used': float(mem_used),
                    'memory_total': float(mem_total)
                })
        return gpus
    except (subprocess.SubprocessError, FileNotFoundError):
        logger.warning("未检测到NVIDIA GPU或nvidia-smi命令不可用")
        return []

def get_system_info():
    """收集系统信息"""
    # CPU信息
    cpu_usage = psutil.cpu_percent(interval=1)
    cpu_count = psutil.cpu_count()
    
    # 内存信息
    memory = psutil.virtual_memory()
    memory_usage = {
        'total': memory.total,
        'used': memory.used,
        'percent': memory.percent
    }
    
    # 系统启动时间
    boot_time = psutil.boot_time()
    uptime_seconds = time.time() - boot_time
    
    # 硬盘使用情况 - 只收集根目录和总体存储
    disks = []
    total_disk_space = 0
    total_disk_used = 0
    
    for part in psutil.disk_partitions(all=False):
        if os.name == 'nt' or part.fstype != 'squashfs':  # 避免Docker容器中的问题
            usage = psutil.disk_usage(part.mountpoint)
            total_disk_space += usage.total
            total_disk_used += usage.used
            
            # 只添加根目录的详细信息
            if part.mountpoint == '/' or (os.name == 'nt' and part.mountpoint == 'C:\\'):
                disks.append({
                    'device': part.device,
                    'mountpoint': '/',  # 统一显示为根目录
                    'total': usage.total,
                    'used': usage.used,
                    'percent': usage.percent
                })
    
    # 添加总存储信息
    if total_disk_space > 0:
        total_percent = (total_disk_used / total_disk_space) * 100
        disks.append({
            'device': 'Total',
            'mountpoint': 'Total',
            'total': total_disk_space,
            'used': total_disk_used,
            'percent': total_percent
        })
    
    # GPU信息
    gpu_info = get_nvidia_gpu_info()
    
    # 获取主机名和IP
    hostname = socket.gethostname()
    try:
        ip_address = socket.gethostbyname(socket.gethostname())
    except socket.gaierror:
        ip_address = "127.0.0.1"  # 无法获取IP时的默认值
    
    # 时间戳
    timestamp = datetime.now().isoformat()
    
    return {
        'client_id': CLIENT_ID,
        'timestamp': timestamp,
        'hostname': hostname,
        'ip_address': ip_address,
        'platform': platform.platform(),
        'cpu': {
            'count': cpu_count,
            'usage_percent': cpu_usage
        },
        'memory': memory_usage,
        'disks': disks,
        'gpu': gpu_info,
        'uptime_seconds': uptime_seconds
    }

def report_to_server(data):
    """将数据发送到服务器"""
    try:
        response = requests.post(SERVER_URL, json=data)
        if response.status_code == 200:
            logger.info(f"数据成功上报到服务器，状态码: {response.status_code}")
            return True
        else:
            logger.error(f"服务器返回错误，状态码: {response.status_code}, 响应: {response.text}")
            return False
    except requests.RequestException as e:
        logger.error(f"上报数据时发生错误: {e}")
        return False

def main():
    logger.info(f"客户端监控服务启动，客户端ID: {CLIENT_ID}")
    
    while True:
        try:
            system_info = get_system_info()
            report_to_server(system_info)
        except Exception as e:
            logger.error(f"获取或上报系统信息时出错: {e}")
        
        time.sleep(REPORT_INTERVAL)

if __name__ == "__main__":
    main()
EOF
    
    # Make client.py executable
    chmod +x /opt/system-monitor/client/client.py
    print_success "Client file created"
}

# Create systemd service files
create_systemd_services() {
    print_section "Creating systemd service files"
    
    # Server service
    cat > /etc/systemd/system/system-monitor-server.service << EOF
[Unit]
Description=System Monitor Server
After=network.target

[Service]
User=root
WorkingDirectory=/opt/system-monitor/server
ExecStart=/opt/system-monitor/server/venv/bin/python /opt/system-monitor/server/server.py
Restart=always
RestartSec=5
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=system-monitor-server

[Install]
WantedBy=multi-user.target
EOF

    # Client service
    cat > /etc/systemd/system/system-monitor-client.service << EOF
[Unit]
Description=System Monitor Client
After=network.target

[Service]
User=root
WorkingDirectory=/opt/system-monitor/client
ExecStart=/opt/system-monitor/client/venv/bin/python /opt/system-monitor/client/client.py
Restart=always
RestartSec=5
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=system-monitor-client

[Install]
WantedBy=multi-user.target
EOF

    print_success "Systemd service files created"
}

# Configure and start the services
configure_services() {
    print_section "Configuring and starting services"
    
    # Reload systemd
    sudo systemctl daemon-reload
    
    # Enable and start server service (only if this is the server)
    if [ "$IS_SERVER" = "y" ]; then
        sudo systemctl enable system-monitor-server
        sudo systemctl start system-monitor-server
        print_success "Server service enabled and started"
    fi
    
    # Enable and start client service
    sudo systemctl enable system-monitor-client
    sudo systemctl start system-monitor-client
    print_success "Client service enabled and started"
    
    # Show status
    if [ "$IS_SERVER" = "y" ]; then
        echo "Server status:"
        sudo systemctl status system-monitor-server --no-pager
    fi
    
    echo "Client status:"
    sudo systemctl status system-monitor-client --no-pager
}

# Main function
main() {
    echo ""
    echo "========================================"
    echo "   系统监控部署脚本 / System Monitor Deployment"
    echo "========================================"
    echo ""
    
    # Ask if this is the server
    read -p "$(echo -e ${YELLOW}"是否将此机器部署为服务器？(y/n): "${NC})" IS_SERVER
    
    # Ask for server IP if this is a client
    if [ "$IS_SERVER" != "y" ]; then
        read -p "$(echo -e ${YELLOW}"请输入服务器IP地址: "${NC})" SERVER_IP
        if [ -z "$SERVER_IP" ]; then
            print_error "服务器IP不能为空，退出..."
            exit 1
        fi
    else
        SERVER_IP="0.0.0.0"  # 服务器本身使用0.0.0.0监听
    fi
    
    # Confirm installation
    if [ "$IS_SERVER" = "y" ]; then
        echo -e "${BLUE}将在此机器上部署服务器和客户端${NC}"
    else
        echo -e "${BLUE}将在此机器上部署客户端，连接到服务器 ${SERVER_IP}${NC}"
    fi
    read -p "$(echo -e ${YELLOW}"确认继续安装？(y/n): "${NC})" CONFIRM
    
    if [ "$CONFIRM" != "y" ]; then
        echo "安装已取消"
        exit 0
    fi
    
    # Start installation
    install_dependencies
    create_directories
    
    # Setup server components
    if [ "$IS_SERVER" = "y" ]; then
        setup_venv "server"
        create_server_files
    fi
    
    # Setup client components
    setup_venv "client"
    create_client_file
    
    # Update server IP in client.py
    sudo sed -i "s|SERVER_IP|$SERVER_IP|g" /opt/system-monitor/client/client.py
    
    # Create systemd services
    create_systemd_services
    
    # Start services
    configure_services
    
    # Print final instructions
    print_section "安装完成！"
    
    if [ "$IS_SERVER" = "y" ]; then
        echo -e "${GREEN}服务器已部署在: http://$SERVER_IP:5000${NC}"
        echo -e "${GREEN}默认管理员账户: admin / admin${NC}"
        print_warning "请尽快登录并修改默认密码！"
    else
        echo -e "${GREEN}客户端已部署并连接到服务器: $SERVER_IP${NC}"
    fi
    
    echo -e "${BLUE}日志文件位置:${NC}"
    echo "  - 服务器: /var/log/syslog (查看方式: journalctl -u system-monitor-server)"
    echo "  - 客户端: /var/log/system-monitor/client.log"
    
    echo -e "\n${YELLOW}如果你需要在更多机器上部署客户端，只需在其他机器上运行此脚本并选择客户端模式即可。${NC}"
}

# Run the main function
main
