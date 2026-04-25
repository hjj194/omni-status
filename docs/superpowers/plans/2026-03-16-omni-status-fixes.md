# Omni-Status Bug & Performance Fixes Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修复 omni-status 监控面板中的功能缺失、安全漏洞、性能问题和存储问题，共 15 项。

**Architecture:** Flask 服务端 + Python 客户端，SQLite 存储，Jinja2 模板渲染。修复按影响范围分组：优先修复崩溃/功能缺失，然后安全，最后性能和存储优化。

**Tech Stack:** Python 3, Flask 2.x, Flask-SQLAlchemy, SQLAlchemy 2.x, Jinja2, psutil, Bootstrap 5

---

## 问题清单（来源）

| # | 类型 | 描述 | 文件 |
|---|------|------|------|
| B1 | 功能缺失 | 管理员无法删除客户端监控 | server.py, dashboard.html |
| B2 | 崩溃 Bug | `last_seen` 为 None 时模板报 AttributeError | dashboard.html:287 |
| B3 | 逻辑 Bug | `save_client_configs()` 在每次上报触发条件错误 | server.py:253 |
| B4 | 兼容性 | `db.engine.execute()` 在 SQLAlchemy 2.x 中已移除 | server.py:189 |
| S1 | XSS | 公告内容使用 `\|safe` 未转义 | dashboard.html:172 |
| S2 | CSRF | 所有表单无 CSRF token 保护 | 所有表单 |
| S3 | 弱凭据 | 默认密码 admin/admin，secret_key 为硬编码字符串 | server.py:41,196 |
| P1 | 性能 | `cpu_percent(interval=1)` 阻塞主循环 1 秒 | client.py:105 |
| P2 | 性能 | `nvidia-smi` 每次上报都 fork 子进程，无缓存 | client.py:82 |
| P3 | 性能 | `/report` 每次做两次全表查询 + 文件写入 | server.py:253 |
| P4 | 性能 | 磁盘遍历在 NFS 挂载时可能阻塞 | client.py:125 |
| ST1 | 存储 | 日志文件无轮转，长期运行后耗尽磁盘 | client.py:22, server.py:22 |
| ST2 | 存储 | systemd 同时写 journal + 文件，日志双份 | system-monitor.sh:382,389 |
| ST3 | 存储 | `client_realtime_data` 内存字典无清理机制 | server.py:180,242 |
| UI1 | UI | 一级面板 GPU 占用率仅看核心使用率，未考虑显存 | dashboard.html:263 |

---

## Chunk 1: 崩溃与兼容性修复（B2、B4）

### Task 1: 修复 `last_seen` 为 None 导致模板崩溃（B2）

**Files:**
- Modify: `server/templates/dashboard.html:287`

**背景：** 离线客户端（从配置文件恢复但从未连接）的 `last_seen` 为 `None`，模板直接调用 `.strftime()` 会崩溃。

- [ ] **Step 1: 定位并修改模板**

在 `dashboard.html` 第 287 行，将：
```html
<div>{{ client.last_seen.strftime('%Y-%m-%d %H:%M') }}</div>
```
改为：
```html
<div>{{ client.last_seen.strftime('%Y-%m-%d %H:%M') if client.last_seen else '从未连接' }}</div>
```

- [ ] **Step 2: 手动验证**

启动服务端，通过 `/import_config` 导入一个 `last_seen` 为空的客户端配置，访问面板展开详情，确认不报错，显示"从未连接"。

- [ ] **Step 3: Commit**
```bash
git add server/templates/dashboard.html
git commit -m "fix: handle None last_seen in dashboard template"
```

---

### Task 2: 修复 `db.engine.execute()` SQLAlchemy 2.x 不兼容（B4）

**Files:**
- Modify: `server/server.py:187-191`

**背景：** `db.engine.execute()` 在 SQLAlchemy 2.0 起已移除，导致应用启动失败。

- [ ] **Step 1: 替换为兼容写法**

将 `server.py` 第 187–191 行：
```python
try:
    with app.app_context():
        db.engine.execute('ALTER TABLE client ADD COLUMN display_order INTEGER DEFAULT 0')
except:
    pass
```
改为：
```python
try:
    with db.engine.connect() as conn:
        conn.execute(db.text('ALTER TABLE client ADD COLUMN display_order INTEGER DEFAULT 0'))
        conn.commit()
except Exception:
    pass  # 列已存在则忽略
```

- [ ] **Step 2: 验证**

重启服务端，确认无启动报错。若数据库为新建，检查 `display_order` 列存在。

- [ ] **Step 3: Commit**
```bash
git add server/server.py
git commit -m "fix: replace deprecated db.engine.execute with SQLAlchemy 2.x compatible API"
```

---

## Chunk 2: 功能补全（B1）与逻辑修复（B3）

### Task 3: 实现管理员删除客户端功能（B1）

**Files:**
- Modify: `server/server.py` — 新增 `/delete_client/<client_id>` 路由
- Modify: `server/templates/dashboard.html` — 在编辑按钮旁添加删除按钮

**背景：** 目前无任何路由或 UI 入口支持删除客户端，管理员无法清理已下线的机器记录。

- [ ] **Step 1: 在 `server.py` 中新增删除路由**

在 `edit_client` 路由之后添加：
```python
@app.route('/delete_client/<client_id>', methods=['POST'])
@login_required
def delete_client(client_id):
    """删除客户端记录 (需要登录)"""
    client = Client.query.get_or_404(client_id)
    hostname = client.hostname

    # 清除实时数据缓存
    client_realtime_data.pop(client_id, None)

    db.session.delete(client)
    db.session.commit()
    save_client_configs()

    logger.info(f"Client deleted: {hostname} (ID: {client_id})")
    flash(f'客户端 "{hostname}" 已删除', 'success')
    return redirect(url_for('dashboard'))
```

- [ ] **Step 2: 在 `dashboard.html` 中添加删除按钮**

将 `dashboard.html` 中管理员工具栏部分（约第 198–202 行）：
```html
{% if is_admin %}
<a href="{{ url_for('edit_client', client_id=client.id) }}" class="btn btn-sm btn-outline-primary" onclick="event.stopPropagation();" title="编辑客户端">
    <i class="bi bi-pencil"></i>
</a>
{% endif %}
```
改为：
```html
{% if is_admin %}
<a href="{{ url_for('edit_client', client_id=client.id) }}" class="btn btn-sm btn-outline-primary" onclick="event.stopPropagation();" title="编辑客户端">
    <i class="bi bi-pencil"></i>
</a>
<form method="post" action="{{ url_for('delete_client', client_id=client.id) }}" style="display:inline;" onclick="event.stopPropagation();" onsubmit="return confirm('确定删除客户端「{{ client.display_name }}」吗？此操作不可撤销。');">
    <button type="submit" class="btn btn-sm btn-outline-danger" title="删除客户端">
        <i class="bi bi-trash"></i>
    </button>
</form>
{% endif %}
```

- [ ] **Step 3: 验证**

以管理员登录，点击某客户端的删除按钮，确认弹出确认框，确认后客户端从面板消失，`client_realtime_data` 中对应条目也被清除。

- [ ] **Step 4: Commit**
```bash
git add server/server.py server/templates/dashboard.html
git commit -m "feat: add delete client functionality for admin"
```

---

### Task 4: 修复 `save_client_configs()` 触发条件逻辑错误（B3）

**Files:**
- Modify: `server/server.py:253-255`

**背景：** `Client.query.all()[:-1]` 去掉的是列表末尾元素，导致判断"是否新客户端"逻辑错误，每次上报都可能触发不必要的文件写入。

- [ ] **Step 1: 修复触发逻辑**

将 `server.py` 第 250–257 行：
```python
db.session.commit()

# 保存配置到文件（当有新客户端时自动保存）
if client.id not in [c.id for c in Client.query.all()[:-1]]:
    save_client_configs()
```
改为：
```python
is_new_client = db.session.is_modified(client) and client.id not in [c.id for c in Client.query.all()]
db.session.commit()

# 仅当有新客户端注册时保存配置
if is_new_client:
    save_client_configs()
```

更简洁的方式是在新建分支时设标志位：
```python
# 在 report() 函数中，获取或创建客户端记录时
is_new = False
client = Client.query.get(data['client_id'])
if client is None:
    is_new = True
    # ... 创建 client ...

# ... 更新字段 ...
db.session.commit()

if is_new:
    save_client_configs()
```

- [ ] **Step 2: 验证**

查看日志，确认同一客户端多次上报时不再重复写入 `server_config.json`，只有新客户端首次上报时才写入。

- [ ] **Step 3: Commit**
```bash
git add server/server.py
git commit -m "fix: only save client configs when a new client registers"
```

---

## Chunk 3: UI 改进（UI1）

### Task 5: GPU 占用率综合考量核心使用率和显存占用（UI1）

**Files:**
- Modify: `server/templates/dashboard.html:261-275`

**背景：** 当前 GPU 占用率仅使用核心 `utilization`，显存跑满但核心空闲时显示为低占用，误导判断。应取核心使用率与显存使用率两者的最大值作为综合指标。

- [ ] **Step 1: 替换 GPU 一级面板的占用率计算**

将 `dashboard.html` 中 GPU 一级展示块（约第 261–275 行）：
```html
<!-- GPU 使用情况 - 如果有 -->
{% if client.gpu %}
{% set avg_gpu_usage = (client.gpu|map(attribute='utilization')|sum / client.gpu|length)|round(1) %}
<div class="metric-label mt-3">
    <span><i class="bi bi-gpu-card metric-icon"></i>GPU</span>
    <span class="metric-value">{{ avg_gpu_usage }}%</span>
</div>
<div class="progress">
    {% set gpu_color = "bg-success" if avg_gpu_usage < 50 else ("bg-warning" if avg_gpu_usage < 80 else "bg-danger") %}
    <div class="progress-bar {{ gpu_color }}" role="progressbar"
        style="width: {{ avg_gpu_usage }}%;"
        aria-valuenow="{{ avg_gpu_usage }}" aria-valuemin="0" aria-valuemax="100">
    </div>
</div>
{% endif %}
```
改为：
```html
<!-- GPU 使用情况 - 如果有 -->
{% if client.gpu %}
{% set ns = namespace(total=0) %}
{% for gpu in client.gpu %}
    {% set mem_pct = (gpu.memory_used / gpu.memory_total * 100) if gpu.memory_total > 0 else 0 %}
    {% set ns.total = ns.total + ([gpu.utilization, mem_pct]|max) %}
{% endfor %}
{% set avg_gpu_usage = (ns.total / client.gpu|length)|round(1) %}
<div class="metric-label mt-3">
    <span><i class="bi bi-gpu-card metric-icon"></i>GPU</span>
    <span class="metric-value">{{ avg_gpu_usage }}%</span>
</div>
<div class="progress">
    {% set gpu_color = "bg-success" if avg_gpu_usage < 50 else ("bg-warning" if avg_gpu_usage < 80 else "bg-danger") %}
    <div class="progress-bar {{ gpu_color }}" role="progressbar"
        style="width: {{ avg_gpu_usage }}%;"
        aria-valuenow="{{ avg_gpu_usage }}" aria-valuemin="0" aria-valuemax="100">
    </div>
</div>
{% endif %}
```

**说明：** 对每块 GPU 分别计算 `max(核心使用率, 显存使用率%)`，再对多卡取平均，确保任一维度饱和都能触发告警色。

- [ ] **Step 2: 验证**

用一台显存高占用（如跑推理但核心空闲）的机器验证：面板应显示黄/红色而非绿色。可在浏览器开发者工具中临时修改 `gpu.memory_used/memory_total` 数值的模板数据来模拟。

- [ ] **Step 3: Commit**
```bash
git add server/templates/dashboard.html
git commit -m "feat: GPU usage indicator now reflects max(core%, vram%)"
```

---

## Chunk 4: 安全修复（S1、S2、S3）

### Task 6: 修复公告内容 XSS（S1）

**Files:**
- Modify: `server/templates/dashboard.html:172`

**背景：** `{{ announcement.content|replace('\n', '<br>')|safe }}` 使用 `|safe` 跳过了 Jinja2 的自动转义，若公告内容包含 `<script>` 等标签则会执行恶意代码。

- [ ] **Step 1: 去掉 `|safe`，改用安全换行**

将 `dashboard.html` 第 172 行：
```html
{{ announcement.content|replace('\n', '<br>')|safe }}
```
改为：
```html
{{ announcement.content|e|replace('\n', '<br>')|safe }}
```

**说明：** 先用 `|e`（等同 `|escape`）对内容进行 HTML 转义（`<` → `&lt;` 等），再替换换行，最后的 `|safe` 仅用于允许 `<br>` 标签，不会再有其他未转义的 HTML。

- [ ] **Step 2: 验证**

在公告内容中输入 `<script>alert(1)</script>`，保存后访问面板，确认弹窗不出现，内容以纯文本形式显示。

- [ ] **Step 3: Commit**
```bash
git add server/templates/dashboard.html
git commit -m "security: escape announcement content to prevent XSS"
```

---

### Task 7: 添加 CSRF 保护（S2）

**Files:**
- Modify: `server/requirements.txt` — 添加 `Flask-WTF`
- Modify: `server/server.py` — 初始化 CSRFProtect
- Modify: `server/templates/dashboard.html` — 删除按钮表单添加 CSRF token
- Modify: `server/templates/settings.html` — 三个表单添加 token
- Modify: `server/templates/announcements.html` — 表单添加 token
- Modify: `server/templates/edit_client.html` — 表单添加 token
- Modify: `server/templates/edit_announcement.html` — 表单添加 token
- Modify: `server/templates/reorder_clients.html` — 表单添加 token
- Modify: `server/templates/login.html` — 表单添加 token

**背景：** 所有 POST 表单（密码修改、删除客户端、清除缓存等）没有 CSRF token，攻击者可以构造恶意页面引诱管理员点击，触发敏感操作。

- [ ] **Step 1: 安装 Flask-WTF**

在 `server/requirements.txt` 末尾添加：
```
Flask-WTF>=1.1.0
```

- [ ] **Step 2: 初始化 CSRFProtect**

在 `server/server.py` 中，`from flask import ...` 之后添加：
```python
from flask_wtf.csrf import CSRFProtect
```

在 `app = Flask(__name__)` 之后添加：
```python
csrf = CSRFProtect(app)
```

同时确保 `app.config['SECRET_KEY']` 已设置（已有，无需修改）。

- [ ] **Step 3: 为所有 POST 表单添加 CSRF token**

在每个含 `<form method="post">` 的模板中，`<form>` 标签内的第一行添加：
```html
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
```

需要修改的表单位置：
- `dashboard.html`：删除客户端表单
- `settings.html`：修改密码表单、导出配置表单、导入配置表单、清除缓存表单
- `announcements.html`：添加/切换/删除公告表单
- `edit_client.html`：编辑客户端表单
- `edit_announcement.html`：编辑公告表单
- `reorder_clients.html`：排序表单
- `login.html`：登录表单

- [ ] **Step 4: 为 `/report` 路由豁免 CSRF（客户端上报接口）**

`/report` 是 API 接口，不走浏览器表单，需豁免：
```python
@app.route('/report', methods=['POST'])
@csrf.exempt
def report():
    ...
```

- [ ] **Step 5: 安装依赖并验证**
```bash
cd server
pip install Flask-WTF
```
重启服务端，访问所有管理页面，确认表单提交正常，直接 curl POST 无 token 的敏感接口返回 400。

- [ ] **Step 6: Commit**
```bash
git add server/requirements.txt server/server.py server/templates/
git commit -m "security: add CSRF protection to all admin forms"
```

---

### Task 8: 强化默认凭据警告（S3）

**Files:**
- Modify: `server/server.py:194-198` — 首次启动时打印更醒目的警告
- Modify: `server/templates/settings.html` — 显示密码强度提示

**背景：** 默认密码 `admin/admin` 无强制修改机制，系统上线后若未修改即为高危。

- [ ] **Step 1: 在创建默认管理员后打印醒目警告**

在 `server.py` 的 `init_db()` 中，创建管理员账户后：
```python
admin = User(username='admin')
admin.set_password('admin')
db.session.add(admin)
db.session.commit()
logger.warning("=" * 60)
logger.warning("警告：已创建默认管理员账户 admin/admin")
logger.warning("请立即登录并在「设置」页面修改默认密码！")
logger.warning("=" * 60)
```

- [ ] **Step 2: 在设置页面检测弱密码并提示**

在 `server.py` 的 `settings()` POST 处理中，修改密码成功后添加弱密码检测：
```python
user.set_password(new_password)
db.session.commit()
if new_password in ('admin', 'password', '123456', 'admin123'):
    flash('密码已更新，但您设置的密码过于简单，建议使用更强的密码', 'warning')
else:
    flash('密码已成功更新', 'success')
```

- [ ] **Step 3: Commit**
```bash
git add server/server.py
git commit -m "security: add prominent warning for default credentials"
```

---

## Chunk 5: 性能优化（P1、P2、P3、P4）

### Task 9: 修复 CPU 采样阻塞主循环（P1）

**Files:**
- Modify: `client/client.py:102-106`

**背景：** `psutil.cpu_percent(interval=1)` 会阻塞 1 秒等待采样窗口，每次上报都损耗 1 秒。

- [ ] **Step 1: 改为非阻塞采样**

在 `client.py` 的 `main()` 启动时，先做一次初始化调用（丢弃返回值），之后循环中使用 `interval=None`：

在 `main()` 函数中 `client_id = get_client_id()` 之后添加：
```python
# 初始化 CPU 采样基准，首次调用返回值无意义
psutil.cpu_percent(interval=None)
```

在 `get_system_info()` 中将：
```python
cpu_usage = psutil.cpu_percent(interval=1)
```
改为：
```python
cpu_usage = psutil.cpu_percent(interval=None)
```

- [ ] **Step 2: 验证**

运行 `python client.py --test`，观察输出速度，确认不再等待 1 秒。CPU 数值仍然是有效的百分比（与上次调用之间的时间窗口计算）。

- [ ] **Step 3: Commit**
```bash
git add client/client.py
git commit -m "perf: use non-blocking cpu_percent to avoid 1s stall per report"
```

---

### Task 10: 缓存 nvidia-smi 可用性（P2）

**Files:**
- Modify: `client/client.py:79-100`

**背景：** 每次上报都 fork `nvidia-smi` 子进程（耗时 100–500ms），且无 GPU 的机器每次都要等异常才知道不可用。

- [ ] **Step 1: 增加模块级缓存变量**

在 `client.py` 顶部的全局变量区域（`CLIENT_ID_FILE` 等定义之后）添加：
```python
_nvidia_available = None  # None=未检测, True=可用, False=不可用
```

- [ ] **Step 2: 修改 `get_nvidia_gpu_info()` 使用缓存**

```python
def get_nvidia_gpu_info():
    """获取NVIDIA GPU信息（缓存可用性状态）"""
    global _nvidia_available

    # 已确认不可用则直接返回
    if _nvidia_available is False:
        return []

    try:
        result = subprocess.run(
            ['nvidia-smi', '--query-gpu=name,utilization.gpu,memory.used,memory.total',
             '--format=csv,noheader,nounits'],
            capture_output=True, text=True, check=True, timeout=5
        )
        _nvidia_available = True

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
        if _nvidia_available is None:
            logger.debug("未检测到NVIDIA GPU或nvidia-smi命令不可用")
        _nvidia_available = False
        return []
```

**说明：** 首次调用会检测并缓存结果，之后无 GPU 的机器直接返回 `[]`，有 GPU 的机器仍每次调用（GPU 状态随时变化需要实时获取）。同时增加了 `timeout=5` 防止 nvidia-smi 挂起。

- [ ] **Step 3: 验证**

在无 GPU 的机器上运行，确认日志中"未检测到 NVIDIA GPU"只出现一次。

- [ ] **Step 4: Commit**
```bash
git add client/client.py
git commit -m "perf: cache nvidia-smi availability to avoid repeated subprocess forks"
```

---

### Task 11: 修复 `/report` 中不必要的全表查询（P3）

**Files:**
- Modify: `server/server.py:219-256`

**背景：** 当前逻辑在每次 `/report` 请求中：
1. `Client.query.get(data['client_id'])` — 正常查询
2. `[c.id for c in Client.query.all()[:-1]]` — 错误的全表查询
3. `save_client_configs()` 内部又 `Client.query.all()` — 再一次全表查询

应改为用标志位记录是否新建了客户端，避免冗余查询。

- [ ] **Step 1: 重构 `report()` 路由中的保存逻辑**

将 `report()` 函数中的 `db.session.commit()` 之后的代码：
```python
db.session.commit()

# 保存配置到文件（当有新客户端时自动保存）
if client.id not in [c.id for c in Client.query.all()[:-1]]:
    save_client_configs()
```
改为（同时修改函数开头，增加 `is_new` 标志）：

在 `client = Client.query.get(data['client_id'])` 之后：
```python
is_new_client = client is None
if client is None:
    max_order = db.session.query(db.func.max(Client.display_order)).scalar() or 0
    client = Client(
        id=data['client_id'],
        hostname=data['hostname'],
        ip_address=data['ip_address'],
        display_name=data['hostname'],
        platform=data['platform'],
        display_order=max_order + 1
    )
    db.session.add(client)
    logger.info(f"New client registered: {data['hostname']} ({data['ip_address']})")
```

在末尾：
```python
db.session.commit()

if is_new_client:
    save_client_configs()
```

- [ ] **Step 2: 验证**

已有客户端上报时，查看日志确认不再触发 `save_client_configs()`。新客户端首次上报时，确认 `server_config.json` 被更新。

- [ ] **Step 3: Commit**
```bash
git add server/server.py
git commit -m "perf: eliminate redundant full-table queries in /report endpoint"
```

---

### Task 12: 为磁盘遍历添加超时保护（P4）

**Files:**
- Modify: `client/client.py:125-144`

**背景：** `psutil.disk_usage(mountpoint)` 在 NFS/CIFS 等网络挂载点无响应时会一直阻塞，导致整个上报周期卡死。

- [ ] **Step 1: 用线程超时包装磁盘查询**

在 `client.py` 顶部已有 `import threading`（若无则添加），然后修改磁盘遍历部分：

```python
import concurrent.futures

# 在 get_system_info() 中替换磁盘遍历逻辑：
def _get_disk_usage(mountpoint):
    return psutil.disk_usage(mountpoint)

disks = []
total_disk_space = 0
total_disk_used = 0

for part in psutil.disk_partitions(all=False):
    if os.name == 'nt' or part.fstype not in ('squashfs', 'tmpfs', 'devtmpfs'):
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(_get_disk_usage, part.mountpoint)
                usage = future.result(timeout=3)  # 3秒超时

            total_disk_space += usage.total
            total_disk_used += usage.used

            if part.mountpoint == '/' or (os.name == 'nt' and part.mountpoint == 'C:\\'):
                disks.append({
                    'device': part.device,
                    'mountpoint': '/',
                    'total': usage.total,
                    'used': usage.used,
                    'percent': usage.percent
                })
        except concurrent.futures.TimeoutError:
            logger.warning(f"获取磁盘信息超时，跳过挂载点: {part.mountpoint}")
        except PermissionError:
            logger.warning(f"没有权限访问挂载点: {part.mountpoint}")
        except Exception as e:
            logger.warning(f"获取磁盘信息时出错 ({part.mountpoint}): {e}")
```

- [ ] **Step 2: Commit**
```bash
git add client/client.py
git commit -m "perf: add 3s timeout for disk usage queries to handle unresponsive NFS mounts"
```

---

## Chunk 6: 存储优化（ST1、ST2、ST3）

### Task 13: 为日志添加轮转（ST1）

**Files:**
- Modify: `client/client.py:22-27`
- Modify: `server/server.py:22-27`

**背景：** 两端都用 `logging.basicConfig(filename=...)` 写无限增长的日志文件，长期运行后会耗尽磁盘。

- [ ] **Step 1: 修改客户端日志为 RotatingFileHandler**

将 `client.py` 第 22–27 行替换为：
```python
from logging.handlers import RotatingFileHandler

_log_handler = RotatingFileHandler(
    LOG_FILE,
    maxBytes=10 * 1024 * 1024,  # 10 MB
    backupCount=3               # 保留 3 个旧文件
)
_log_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

logging.basicConfig(
    level=logging.INFO,
    handlers=[_log_handler]
)
```

- [ ] **Step 2: 修改服务端日志为 RotatingFileHandler**

将 `server.py` 第 22–27 行做相同修改：
```python
from logging.handlers import RotatingFileHandler

_log_handler = RotatingFileHandler(
    log_file,
    maxBytes=10 * 1024 * 1024,  # 10 MB
    backupCount=5               # 服务端保留 5 个旧文件
)
_log_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

logging.basicConfig(
    level=logging.INFO,
    handlers=[_log_handler]
)
```

**上限说明：**
- 客户端：最大 10MB × 4 = 40MB（含备份），按 60s 上报间隔约可存 1.5 年
- 服务端：最大 10MB × 6 = 60MB

- [ ] **Step 3: Commit**
```bash
git add client/client.py server/server.py
git commit -m "fix: use RotatingFileHandler to prevent unbounded log growth"
```

---

### Task 14: 消除日志双份写入（ST2）

**Files:**
- Modify: `system-monitor.sh:219-237`（服务端 systemd service）
- Modify: `system-monitor.sh:381-397`（客户端 systemd service）

**背景：** systemd service 配置 `StandardOutput=journal` 同时 Python 程序也写文件日志，等于双份存储。

- [ ] **Step 1: 修改 systemd service 配置，将 stdout/stderr 重定向到 null**

将 `system-monitor.sh` 中创建服务端 service 文件的部分（约第 219–237 行）：
```bash
StandardOutput=journal
StandardError=journal
```
改为：
```bash
StandardOutput=null
StandardError=null
```

对客户端 service 部分（约第 381–397 行）做相同修改：
```bash
StandardOutput=null
StandardError=null
```

**说明：** Python 程序已经通过 RotatingFileHandler 写文件日志，journal 中的重复写入没有额外价值。若需要 journalctl 支持，可以保留 `StandardError=journal` 只捕获启动崩溃信息，但 `StandardOutput=null`。

- [ ] **Step 2: 注意：此修改仅影响新安装**

已安装的系统需要手动修改 `/etc/systemd/system/system-monitor-{server,client}.service` 并 `systemctl daemon-reload`。可在脚本注释中说明。

- [ ] **Step 3: Commit**
```bash
git add system-monitor.sh
git commit -m "fix: prevent duplicate log storage by silencing systemd journal stdout"
```

---

### Task 15: 为 `client_realtime_data` 添加过期清理（ST3）

**Files:**
- Modify: `server/server.py:180`, `server/server.py:259-346`

**背景：** `client_realtime_data` 是全局内存字典，客户端删除后对应条目不会被清除（现在 Task 3 已处理删除时的清理），但长期离线的客户端数据也会一直驻留内存。

- [ ] **Step 1: 在 `dashboard()` 路由中清理过期数据**

在 `dashboard()` 函数开头（`clients = Client.query...` 之前）添加过期清理：
```python
@app.route('/')
def dashboard():
    """主仪表盘页面"""
    # 清理孤立的实时数据（客户端已从数据库删除但缓存未清理）
    valid_client_ids = {c.id for c in Client.query.with_entities(Client.id).all()}
    stale_ids = [cid for cid in client_realtime_data if cid not in valid_client_ids]
    for cid in stale_ids:
        del client_realtime_data[cid]

    clients = Client.query.order_by(Client.display_order).all()
    # ... 其余逻辑不变
```

- [ ] **Step 2: Commit**
```bash
git add server/server.py
git commit -m "fix: clean up stale realtime data for deleted clients on dashboard load"
```

---

## 执行顺序建议

```
Chunk 1 (B2, B4) → Chunk 2 (B1, B3) → Chunk 3 (UI1)
→ Chunk 4 (S1, S2, S3) → Chunk 5 (P1-P4) → Chunk 6 (ST1-ST3)
```

崩溃和功能性问题优先，安全次之，性能和存储最后。每个 Task 独立可提交，不互相依赖（除 Task 3 删除功能和 Task 15 清理逻辑有轻微关联外）。

---

## 文件改动总览

| 文件 | 涉及 Task |
|------|-----------|
| `server/server.py` | T2, T3, T4, T8, T11, T15 |
| `server/templates/dashboard.html` | T1, T3, T5, T6, T7 |
| `server/templates/settings.html` | T7 |
| `server/templates/announcements.html` | T7 |
| `server/templates/edit_client.html` | T7 |
| `server/templates/edit_announcement.html` | T7 |
| `server/templates/reorder_clients.html` | T7 |
| `server/templates/login.html` | T7 |
| `server/requirements.txt` | T7 |
| `client/client.py` | T9, T10, T12, T13 |
| `system-monitor.sh` | T14 |
