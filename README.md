# 系统监控仪表盘 - 部署指南

本文档提供了系统监控仪表盘的详细部署步骤和管理说明。

## 0. 功能概览

- **实时仪表盘**(`/`)—— 公开可见,展示所有客户端的 CPU / 内存 / 磁盘 / GPU 实时占用,以及 30 天可用性条
- **GPU 使用报告**(`/gpu-report`)—— 管理员登录后可见
  - 顶部摘要:在线客户端数 / GPU 总数 / 当前空闲 / 本周异常
  - **本周 AI 摘要**(可选,需配 `ANTHROPIC_API_KEY`)—— 周一 09:00 自动生成中文周报
  - **当前空闲 GPU**:VRAM < 15% 的卡,实时
  - **7 天 VRAM 占用热力图**:每客户端每 GPU 168 个小时的占用情况
  - **长期空闲 GPU**:7 天 VRAM 均值 < 20% 且低占用 ≥ 120 小时的卡(用于发现被遗忘/无人调度的资源)
  - **硬件异常记录**:7 天内 nvidia-smi 报错的 GPU
- **单卡故障隔离**:某张 GPU 驱动挂掉/XID 错误时,仅该卡红色标注"硬件异常",**整机仍显示在线**,其他卡正常监控
- **AI 周报**(可选):管理员配置 API key 后,每周一早上 9:00 自动生成中文 markdown 摘要,涵盖整体利用率、长期空闲、硬件异常、可调度资源

## 1. 文件结构

```
omni-status/
│
├── server/                        # 服务端组件
│   ├── server.py                  # Flask 主程序 + 实时 dashboard
│   ├── gpu_report.py              # GPU 报告 Blueprint(模型/聚合/调度/LLM agent)
│   ├── auth.py                    # 共享 login_required 装饰器
│   ├── templates/
│   │   ├── dashboard.html         # 主仪表盘(实时)
│   │   ├── gpu_report.html        # GPU 使用报告(管理员)
│   │   ├── login.html             # 登录页
│   │   ├── reorder_clients.html   # 客户端排序
│   │   ├── settings.html          # 系统设置
│   │   ├── announcements.html     # 公告管理
│   │   └── edit_*.html            # 编辑表单
│   └── requirements.txt           # 服务端依赖
│
├── client/                        # 客户端组件
│   ├── client.py                  # 客户端主程序(60s 上报一次)
│   └── requirements.txt           # 客户端依赖
│
├── tests/                         # 测试套件(pytest)
│   ├── conftest.py                # 公共 fixtures
│   └── test_*.py                  # 11 个测试文件
│
├── docs/superpowers/              # 设计文档与实施计划
│   ├── specs/                     # 设计规范
│   └── plans/                     # 实施计划
│
├── pytest.ini                     # 测试配置(coverage 阈值 80%)
├── system-monitor.sh              # 一键部署管理脚本
└── README.md                      # 本文件
```

## 2. 手动部署步骤

### 2.1 服务端部署

1. **准备环境**

   ```bash
   sudo apt-get update
   sudo apt-get install -y python3 python3-pip python3-venv sqlite3

   sudo mkdir -p /opt/system-monitor/server
   sudo mkdir -p /etc/system-monitor/server
   sudo mkdir -p /var/log/system-monitor
   ```

2. **复制文件**

   ```bash
   sudo cp -r server/* /opt/system-monitor/server/
   sudo chmod +x /opt/system-monitor/server/server.py
   ```

3. **创建虚拟环境并安装依赖**

   ```bash
   cd /opt/system-monitor/server
   sudo python3 -m venv venv
   sudo venv/bin/pip install -r requirements.txt
   ```

   `requirements.txt` 包含:Flask、Flask-SQLAlchemy、APScheduler、tzlocal、anthropic、Markdown、bleach。

4. **(可选)配置 LLM 周报**

   配置 `ANTHROPIC_API_KEY` 才会启用 AI 周报。两种方式:

   ```bash
   # 方式 A:写入 systemd 单元
   # 方式 B:写入 /etc/system-monitor/.env(自行加载)
   ```

   未配置时 `/gpu-report` 仍正常工作,只是 AI 摘要区域显示"尚未生成"。

5. **创建 systemd 服务**

   ```bash
   sudo bash -c 'cat > /etc/systemd/system/system-monitor-server.service << EOF
   [Unit]
   Description=System Monitor Server (omni-status)
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
   Environment="ANTHROPIC_API_KEY=sk-ant-..."

   [Install]
   WantedBy=multi-user.target
   EOF'
   ```

6. **启动服务**

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable system-monitor-server
   sudo systemctl start system-monitor-server
   ```

### 2.2 客户端部署

1. **准备环境**

   ```bash
   sudo apt-get update
   sudo apt-get install -y python3 python3-pip python3-venv

   sudo mkdir -p /opt/system-monitor/client
   sudo mkdir -p /etc/system-monitor
   sudo mkdir -p /var/log/system-monitor
   ```

2. **复制文件**

   ```bash
   sudo cp -r client/* /opt/system-monitor/client/
   sudo chmod +x /opt/system-monitor/client/client.py
   ```

3. **虚拟环境与依赖**

   ```bash
   cd /opt/system-monitor/client
   sudo python3 -m venv venv
   sudo venv/bin/pip install -r requirements.txt
   ```

4. **创建配置文件**

   ```bash
   sudo bash -c 'cat > /etc/system-monitor/client.conf << EOF
   [server]
   url = http://YOUR_SERVER_IP:5000/report
   report_interval = 60
   EOF'
   ```

5. **创建并启动服务**

   ```bash
   sudo bash -c 'cat > /etc/systemd/system/system-monitor-client.service << EOF
   [Unit]
   Description=System Monitor Client (omni-status)
   After=network.target

   [Service]
   User=root
   WorkingDirectory=/opt/system-monitor/client
   ExecStart=/opt/system-monitor/client/venv/bin/python /opt/system-monitor/client/client.py
   Restart=always
   RestartSec=5

   [Install]
   WantedBy=multi-user.target
   EOF'

   sudo systemctl daemon-reload
   sudo systemctl enable --now system-monitor-client
   ```

## 3. 配置参数

### 3.1 `/etc/system-monitor/server/server.conf`

```ini
[server]
host = 0.0.0.0
port = 5000
secret_key = CHANGE_ME_TO_A_RANDOM_SECRET
debug = false

[gpu_report]
retention_days = 7                    ; 小时数据保留天数
idle_vram_threshold = 15              ; "当前空闲" VRAM 上限(%)
heatmap_low_threshold = 20            ; 热力图绿色阈值
heatmap_high_threshold = 70           ; 热力图红色阈值
longterm_vram_threshold = 20          ; 长期空闲 VRAM 均值阈值
longterm_hours_required = 120         ; 长期空闲所需低占用小时数
llm_model = claude-haiku-4-5-20251001
llm_schedule_cron = 0 9 * * 1         ; 周一 09:00
llm_report_retention = 12             ; 保留最近 N 条 AI 摘要
timezone =                            ; 留空则自动检测;显式如 "Asia/Shanghai"
```

### 3.2 环境变量

| 变量 | 必需 | 说明 |
|---|---|---|
| `ANTHROPIC_API_KEY` | 否 | 配置后启用 AI 周报。未配置时 AI 摘要区显示"尚未生成",其他功能不受影响 |
| `SECRET_KEY` | 否 | Flask session 密钥,生产环境务必设置 |
| `FLASK_TESTING_DB` | 否 | 仅测试用,覆盖 SQLite URI(如 `sqlite:///:memory:`) |

### 3.3 `/etc/system-monitor/client.conf`

```ini
[server]
url = http://server-ip:5000/report
report_interval = 60                  ; 上报间隔(秒)
```

## 4. 使用管理脚本部署

`system-monitor.sh` 脚本提供更简便的部署:

```bash
curl -O https://raw.githubusercontent.com/hjj194/omni-status/main/system-monitor.sh
chmod +x system-monitor.sh
sudo ./system-monitor.sh
```

通过交互式菜单完成配置(选 `1` 装服务端,选 `2` 装客户端)。

## 5. 管理与运维

### 5.1 服务管理

```bash
sudo systemctl {start|stop|restart|status} system-monitor-server
sudo systemctl {start|stop|restart|status} system-monitor-client
```

### 5.2 查看日志

```bash
sudo journalctl -u system-monitor-server -f
sudo journalctl -u system-monitor-client -f

sudo tail -f /var/log/system-monitor/server.log
sudo tail -f /var/log/system-monitor/client.log
```

> 提示:如果系统日志目录无写权限,服务端/客户端会自动 fallback 到本地目录或 stderr,**不会因日志权限问题而崩溃**。

### 5.3 数据库

- SQLite 文件:`/opt/system-monitor/server/monitor.db`
- 表清单:`user`、`client`、`announcement`、`uptime_record`(每日)、`gpu_hourly_usage`(每小时)、`llm_report`(AI 周报)
- `gpu_hourly_usage` 自动保留 7 天,旧数据由后台任务每小时 `:05` 清理
- `llm_report` 仅保留最近 12 条,周日凌晨 03:00 清理

## 6. 访问仪表盘

部署完成后:

| 路径 | 权限 | 内容 |
|---|---|---|
| `http://server-ip:5000/` | 公开 | 实时 dashboard |
| `http://server-ip:5000/login` | 公开 | 管理员登录 |
| `http://server-ip:5000/gpu-report` | 登录 | **GPU 使用报告(本次新增)** |
| `http://server-ip:5000/announcements` | 登录 | 公告管理 |
| `http://server-ip:5000/settings` | 登录 | 系统设置 |
| `http://server-ip:5000/reorder` | 登录 | 调整客户端顺序 |

初始管理员账户:`admin / admin` —— **首次登录后请立即在 设置 页面修改默认密码**。

## 7. 测试

```bash
cd /path/to/omni-status
pip install pytest pytest-cov pytest-flask
pytest                                # 跑全部测试
pytest --cov-report=html              # 生成 HTML 覆盖率报告(htmlcov/)
pytest tests/test_gpu_hourly_ingest.py -v  # 跑特定文件
```

当前测试套件:**100 个测试,83% 覆盖率**(超过项目要求的 80% 阈值)。

## 8. 故障排除

### 8.1 客户端"整机掉线"

**已修复**(本次):某张 GPU 出现 nvidia-smi `[N/A]` 错误时,过去会导致客户端无法上报,整机显示掉线。现在该卡单独标红,其他 GPU 和整机状态正常。

### 8.2 检查服务

```bash
sudo systemctl status system-monitor-server
sudo systemctl status system-monitor-client
```

### 8.3 客户端连通性测试

```bash
cd /opt/system-monitor/client
sudo venv/bin/python client.py --test
```

成功:`✅ 服务器连接成功！数据已上报。`
失败:`❌ 服务器连接失败！请检查网络和服务器地址。`

### 8.4 GPU 报告显示"尚未生成"

- AI 摘要需要 `ANTHROPIC_API_KEY` 环境变量
- 周一 09:00 第一次自动触发(本地时区,可在 `[gpu_report] timezone` 配置)
- 手动触发(REPL):
  ```bash
  cd /opt/system-monitor/server
  sudo venv/bin/python -c "
  from server import app
  from gpu_report import generate_llm_summary
  with app.app_context():
      generate_llm_summary()
  "
  ```

### 8.5 检查热力图无数据

- 客户端必须运行至少一个完整小时,`gpu_hourly_usage` 才会有第一行
- `sqlite3 /opt/system-monitor/server/monitor.db 'select count(*) from gpu_hourly_usage'`
- 如果客户端在线但表里仍然为空,检查 `/var/log/system-monitor/server.log` 是否有 `GPU 小时样本写入失败` 警告

## 9. 相关文档

- [设计规范](docs/superpowers/specs/2026-04-24-gpu-usage-report-and-alerts-design.md) —— 16 节完整设计
- [实施计划](docs/superpowers/plans/2026-04-24-gpu-usage-report-and-low-idle-alerts.plan.md) —— 35 任务的分阶段执行计划

如需更多帮助,请参考项目 GitHub 仓库或提交 Issue。
