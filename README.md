# 系统监控仪表盘 (System Monitoring Dashboard)

![系统监控仪表盘](https://via.placeholder.com/800x400?text=系统监控仪表盘)

一个轻量级、响应式的系统资源监控仪表盘，可用于监控多台服务器的 CPU、内存、存储和 GPU 使用情况。

## 功能特点

### 📊 实时监控

- **多项系统指标**: CPU、内存、存储和 GPU (如有) 使用率
- **实时更新**: 通过客户端程序定期收集并上报数据
- **历史数据**: 提供一周、一个月、半年和一年的历史数据图表

### 💻 友好界面

- **响应式设计**: 完美适配桌面和移动设备
- **两级界面**: 简洁的卡片视图 + 可展开的详细信息
- **可自定义**: 管理员可以调整监控卡片的显示顺序
- **直观图表**: 清晰展示历史数据趋势

### 🔒 管理功能

- **管理员认证**: 安全的登录系统保护管理功能
- **客户端管理**: 可编辑客户端显示名称和物理位置
- **自动发现**: 新客户端自动添加到监控列表

### 🚀 简单部署

- **一键安装**: 通过部署脚本快速安装服务端和客户端
- **系统服务**: 自动创建系统服务确保程序持续运行
- **跨平台支持**: 支持基于 Debian 和 RHEL 的 Linux 系统

## 系统架构

![系统架构](https://via.placeholder.com/800x400?text=系统架构图)

- **服务端**: 基于 Flask 的 Web 应用，提供仪表盘界面和 API
- **客户端**: Python 脚本，收集系统信息并上报到服务端
- **数据库**: SQLite 数据库存储监控数据和客户端信息
- **系统服务**: 通过 systemd 管理服务端和客户端程序

## 快速开始

### 部署服务端

1. 下载部署脚本
```bash
curl -O https://raw.githubusercontent.com/yourusername/omni-status/main/deploy.sh
chmod +x deploy.sh
```

2. 运行部署脚本
```bash
sudo ./deploy.sh
```

3. 按照提示选择 `y` 将当前机器部署为服务器
```
是否将此机器部署为服务器？(y/n): y
```

4. 安装完成后，您可以通过 `http://服务器IP:5000` 访问仪表盘
```
服务器已部署在: http://your_server_ip:5000
默认管理员账户: admin / admin
```

### 部署客户端

1. 在需要监控的机器上下载部署脚本
```bash
curl -O https://raw.githubusercontent.com/yourusername/omni-status/main/deploy.sh
chmod +x deploy.sh
```

2. 运行部署脚本
```bash
sudo ./deploy.sh
```

3. 按照提示选择 `n` 将当前机器部署为客户端，并输入服务器 IP 地址
```
是否将此机器部署为服务器？(y/n): n
请输入服务器IP地址: your_server_ip
```

4. 安装完成后，客户端将自动连接到服务器并开始上报数据

## 使用指南

### 查看监控数据

- 访问 `http://服务器IP:5000` 打开仪表盘
- 每个客户端机器以卡片形式显示在仪表盘上
- 卡片显示机器的基本信息和资源使用率
- 点击卡片可展开查看更多详细信息
- 点击历史数据按钮可查看历史趋势图表

### 管理功能

1. **登录管理员账户**
   - 点击右上角的"管理员登录"按钮
   - 使用默认凭据 (admin/admin) 或您设置的凭据登录

2. **编辑客户端信息**
   - 登录后，每个卡片右上角会显示编辑按钮
   - 可以编辑显示名称、物理地址和备注信息

3. **调整显示顺序**
   - 登录后，点击顶部导航栏的"排序"按钮
   - 通过拖拽调整客户端卡片的显示顺序
   - 点击"保存顺序"按钮保存更改

## 系统要求

### 服务端

- Linux 系统 (Debian/Ubuntu 或 RHEL/CentOS)
- Python 3.6+
- 2GB+ 内存 (推荐)
- 1GB+ 磁盘空间 (用于存储历史数据)

### 客户端

- Linux 系统 (Debian/Ubuntu 或 RHEL/CentOS)
- Python 3.6+
- 100MB+ 磁盘空间

## 常见问题

**Q: 客户端显示为离线状态怎么办？**

A: 检查以下几点：
- 确保客户端服务正在运行: `systemctl status system-monitor-client`
- 检查客户端日志: `cat /var/log/system-monitor/client.log`
- 确认服务器和客户端之间的网络连接正常
- 检查防火墙是否允许客户端连接到服务器的 5000 端口

**Q: 如何修改默认管理员密码？**

A: 目前需要直接修改数据库：
```bash
cd /opt/system-monitor/server
source venv/bin/activate
python -c "from server import app, db, User; app.app_context().push(); user = User.query.filter_by(username='admin').first(); user.set_password('your_new_password'); db.session.commit()"
```

**Q: 如何调整客户端上报频率？**

A: 编辑客户端配置文件并重启服务：
```bash
sudo nano /opt/system-monitor/client/client.py  # 修改 REPORT_INTERVAL 的值（秒）
sudo systemctl restart system-monitor-client
```

## 项目路线图

- [ ] 添加更多系统指标 (网络流量、进程信息等)
- [ ] 支持告警设置和通知功能
- [ ] 添加管理员密码修改界面
- [ ] 支持 HTTPS 和更多安全特性
- [ ] 添加更多数据可视化选项

## 贡献指南

欢迎贡献代码、报告问题或提出功能建议。请通过 GitHub 提交 Issue 或 Pull Request。

## 许可证

[MIT License](LICENSE)
