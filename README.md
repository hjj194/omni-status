# 系统监控仪表盘 - 部署指南

本文档提供了系统监控仪表盘的详细部署步骤和管理说明。

## 1. 文件结构

项目文件结构组织如下：

```
system-monitor/
│
├── server/                      # 服务端组件
│   ├── server.py                # 服务端主程序
│   ├── templates/               # HTML模板
│   │   ├── dashboard.html       # 主仪表盘页面
│   │   ├── edit_client.html     # 客户端编辑页面
│   │   ├── login.html           # 登录页面
│   │   ├── reorder_clients.html # 排序页面
│   │   ├── settings.html        # 设置页面
│   │   └── client_history.html  # 历史数据页面
│   └── requirements.txt         # 服务端依赖
│
├── client/                      # 客户端组件
│   ├── client.py                # 客户端主程序
│   └── requirements.txt         # 客户端依赖
│
├── system-monitor.sh            # 管理脚本
└── deployment-guide.md          # 部署指南
```

## 2. 手动部署步骤

### 2.1 服务端部署

1. **准备环境**

   ```bash
   # 安装依赖
   sudo apt-get update
   sudo apt-get install -y python3 python3-pip python3-venv sqlite3
   
   # 创建目录
   sudo mkdir -p /opt/system-monitor/server
   sudo mkdir -p /etc/system-monitor/server
   sudo mkdir -p /var/log/system-monitor
   ```

2. **复制文件**

   ```bash
   # 复制服务端文件
   sudo cp -r server/* /opt/system-monitor/server/
   
   # 设置权限
   sudo chmod +x /opt/system-monitor/server/server.py
   ```

3. **创建虚拟环境并安装依赖**

   ```bash
   # 创建虚拟环境
   cd /opt/system-monitor/server
   sudo python3 -m venv venv
   sudo venv/bin/pip install -r requirements.txt
   ```

4. **创建服务**

   ```bash
   # 创建systemd服务
   sudo bash -c 'cat > /etc/systemd/system/system-monitor-server.service << EOF
   [Unit]
   Description=System Monitor Server
   After=network.target
   
   [Service]
   User=root
   WorkingDirectory=/opt/system-monitor/server
   ExecStart=/opt/system-monitor/server/venv/bin/python /opt/system-monitor/server/server.py
   Restart=always
   RestartSec=5
   StandardOutput=journal
   StandardError=journal
   Environment="FLASK_APP=server"
   
   [Install]
   WantedBy=multi-user.target
   EOF'
   ```

5. **启动服务**

   ```bash
   # 启用并启动服务
   sudo systemctl daemon-reload
   sudo systemctl enable system-monitor-server
   sudo systemctl start system-monitor-server
   ```

### 2.2 客户端部署

1. **准备环境**

   ```bash
   # 安装依赖
   sudo apt-get update
   sudo apt-get install -y python3 python3-pip python3-venv
   
   # 创建目录
   sudo mkdir -p /opt/system-monitor/client
   sudo mkdir -p /etc/system-monitor/client
   sudo mkdir -p /var/log/system-monitor
   ```

2. **复制文件**

   ```bash
   # 复制客户端文件
   sudo cp -r client/* /opt/system-monitor/client/
   
   # 设置权限
   sudo chmod +x /opt/system-monitor/client/client.py
   ```

3. **创建虚拟环境并安装依赖**

   ```bash
   # 创建虚拟环境
   cd /opt/system-monitor/client
   sudo python3 -m venv venv
   sudo venv/bin/pip install -r requirements.txt
   ```

4. **创建配置文件**

   ```bash
   # 创建配置文件
   sudo bash -c 'cat > /etc/system-monitor/client/client.conf << EOF
   [server]
   url = http://你的服务器IP:5000/report
   report_interval = 60
   EOF'
   ```

5. **创建服务**

   ```bash
   # 创建systemd服务
   sudo bash -c 'cat > /etc/systemd/system/system-monitor-client.service << EOF
   [Unit]
   Description=System Monitor Client
   After=network.target
   
   [Service]
   User=root
   WorkingDirectory=/opt/system-monitor/client
   ExecStart=/opt/system-monitor/client/venv/bin/python /opt/system-monitor/client/client.py
   Restart=always
   RestartSec=5
   StandardOutput=journal
   StandardError=journal
   
   [Install]
   WantedBy=multi-user.target
   EOF'
   ```

6. **启动服务**

   ```bash
   # 启用并启动服务
   sudo systemctl daemon-reload
   sudo systemctl enable system-monitor-client
   sudo systemctl start system-monitor-client
   ```

## 3. 使用管理脚本部署

`system-monitor.sh` 脚本提供了更简便的部署和管理方式：

1. **下载管理脚本**

   ```bash
   curl -O https://raw.githubusercontent.com/hjj194/omni-status/main/system-monitor.sh
   chmod +x system-monitor.sh
   ```

2. **运行脚本**

   ```bash
   sudo ./system-monitor.sh
   ```

3. **通过交互式菜单进行操作**
   - 选择 `1` 安装服务端
   - 选择 `2` 安装客户端
   - 按照提示完成配置

## 4. 管理系统

无论是手动部署还是使用脚本部署，系统都可以通过以下命令进行管理：

### 4.1 服务管理

```bash
# 启动服务
sudo systemctl start system-monitor-server
sudo systemctl start system-monitor-client

# 停止服务
sudo systemctl stop system-monitor-server
sudo systemctl stop system-monitor-client

# 重启服务
sudo systemctl restart system-monitor-server
sudo systemctl restart system-monitor-client

# 查看状态
sudo systemctl status system-monitor-server
sudo systemctl status system-monitor-client
```

### 4.2 查看日志

```bash
# 查看服务日志
sudo journalctl -u system-monitor-server
sudo journalctl -u system-monitor-client

# 查看应用日志
sudo cat /var/log/system-monitor/server.log
sudo cat /var/log/system-monitor/client.log
```

### 4.3 配置文件

```bash
# 编辑服务端配置
sudo nano /etc/system-monitor/server/server.conf

# 编辑客户端配置
sudo nano /etc/system-monitor/client/client.conf
```

## 5. 访问仪表盘

部署完成后，您可以通过以下地址访问仪表盘：

```
http://服务器IP:5000
```

初始管理员账户：
- 用户名：admin
- 密码：admin

**注意**：请在首次登录后立即修改默认密码。

## 6. 故障排除

如果您遇到任何问题，请尝试以下步骤：

1. **检查服务状态**
   ```bash
   sudo systemctl status system-monitor-server
   sudo systemctl status system-monitor-client
   ```

2. **查看日志**
   ```bash
   sudo journalctl -u system-monitor-server -n 100
   sudo journalctl -u system-monitor-client -n 100
   sudo cat /var/log/system-monitor/server.log
   sudo cat /var/log/system-monitor/client.log
   ```

3. **检查网络连接**
   - 确保服务器的 5000 端口已开放
   - 确保客户端可以访问服务器
   ```bash
   sudo curl -v http://服务器IP:5000
   ```

4. **测试客户端连接**
   ```bash
   cd /opt/system-monitor/client
   sudo venv/bin/python client.py --test
   ```

如需更多帮助，请参考项目 GitHub 仓库或提交 Issue。
