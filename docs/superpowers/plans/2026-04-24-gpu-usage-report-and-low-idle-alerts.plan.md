# Plan: GPU 使用汇总报告与低使用提示

## Summary

为 omni-status 项目新增管理员专用的 GPU 使用量报告页面(`/gpu-report`),持久化小时级 VRAM/util 指标到 SQLite,提供 7 天热力图 + 长期空闲检测 + 硬件异常追踪 + 每周 Claude Haiku 自动生成的自然语言摘要。同步修复客户端"单卡故障导致整机掉线"的上报 bug,把 GPU 数据契约升级为带 `status` 字段的结构,并让 dashboard 单独标红坏卡而保持整机在线。

## User Story

As a lab advisor,
I want 一个登录后可见的 GPU 使用报告页面(内含周报、热力图、空闲清单、异常卡)以及客户端单卡故障的隔离展示,
So that 我能快速发现资源分配问题、识别长期被闲置的 GPU、定位故障硬件,而不需要逐台机器 ssh 检查,也不会因为一张卡坏了就以为整机掉了。

## Problem → Solution

**Current state:**
- 只有实时 dashboard,无历史时间序列
- 客户端 `float('[N/A]')` 抛 `ValueError` 未被捕获 → 整次 `/report` 跳过 → `last_seen` 超时 → 整机显示 offline
- 导师无法回答:"这张卡过去一周被用了多久?"、"有没有哪些卡长期闲着?"、"哪些硬件在报错?"

**Desired state:**
- `/gpu-report`(admin-only)提供顶部摘要 + 当前空闲卡 + 7 天 VRAM 热力图 + 长期空闲表 + 硬件异常表 + 周一 09:00 自动生成的 LLM 中文周报
- 单卡解析失败时,该卡 `status='error'` 独立标红,其它卡和整机正常
- 全部数据流对现有 dashboard 路径零影响(异常隔离,失败静默降级)

## Metadata

- **Complexity**: Large(18 个文件变更,~35 个任务,预计 1200+ 行代码 + 测试)
- **Source Spec**: `docs/superpowers/specs/2026-04-24-gpu-usage-report-and-alerts-design.md`
- **Spec Phase**: 覆盖 spec 的 16 节全部,按 spec 第 14 节 6 阶段顺序分解
- **Estimated Files**: 18(8 新建,10 修改)

---

## UX Design

### Before —— Dashboard 客户端卡片(单 GPU 坏的情况)

```
┌──────────────────────────────┐
│ ● lab-srv-03  [OFFLINE]      │   ← 整机被错误标记下线
│                              │
│   (全部指标不可见)             │   ← 无法定位到底哪里坏了
│                              │
│   last_seen: 23 分钟前        │
└──────────────────────────────┘
```

### After —— Dashboard 单卡错误独立展示

```
┌──────────────────────────────┐
│ ● lab-srv-03  [ONLINE]       │   ← 整机仍然在线
│   CPU 12%  Memory 40%        │
│                              │
│   GPU 详情:                   │
│   ┌──────────────────────┐   │
│   │ RTX 3090(idx 0)   78%│   │   ← 好卡照常显示
│   ├──────────────────────┤   │
│   │ ⚠ RTX 3090(idx 1)    │   │   ← 坏卡红框标注
│   │   硬件/驱动异常        │   │
│   │   nvidia-smi: [N/A]   │   │
│   │   上次正常 14 分钟前   │   │
│   ├──────────────────────┤   │
│   │ RTX 3090(idx 2)    3%│   │
│   └──────────────────────┘   │
└──────────────────────────────┘
```

### After —— 新增 /gpu-report 页面(admin 登录后可见)

```
┌────────────────────────────────────────────────────────────┐
│  GPU 使用报告                             [返回仪表盘][登出] │
├────────────────────────────────────────────────────────────┤
│  [在线 10/12] [GPU 38] [空闲 7] [异常 3]                     │
│                                                            │
│  ┌── 本周摘要(Claude Haiku 自动生成) ─────────────────────┐│
│  │ 过去一周实验室 GPU 整体利用率偏低(均 22%)...          ││
│  │ [查看历史摘要]                                          ││
│  └────────────────────────────────────────────────────────┘│
│                                                            │
│  ① 当前空闲 GPU                                             │
│  [ lab-srv-02 GPU 1 ] [ lab-srv-02 GPU 3 ] ...            │
│                                                            │
│  ② 7 天 VRAM 占用热力图                                     │
│  lab-srv-01 GPU 0  ████████████████████████...   (168h)   │
│  lab-srv-02 GPU 0  ░░████▓▓░░████▓▓░░...                  │
│  [Legend: ░ 空闲 ▓ 中等 █ 高占用 ▒ 故障/无数据]              │
│                                                            │
│  ③ 长期空闲 GPU(VRAM 均值 < 20%,低占用小时 ≥ 120)         │
│  [表格]                                                     │
│                                                            │
│  ④ 硬件异常记录(error_count > 0)                            │
│  [表格]                                                     │
└────────────────────────────────────────────────────────────┘
```

### Interaction Changes

| Touchpoint | Before | After | Notes |
|---|---|---|---|
| `/` GPU 卡片区 | 单个平均值进度条 | 单个平均值 + 详情内单独标红坏卡 | 整机在线状态基于 `last_seen`,不变 |
| `/report` | 只写 `client_realtime_data` + `UptimeRecord` | 同上 + `GpuHourlyUsage` 小时聚合 | 新写入包 try/except |
| `/gpu-report` | 404 | 新页面(admin only) | Blueprint 注册 |
| client `get_nvidia_gpu_info()` | 单卡解析失败 → 抛异常,丢弃整次报告 | 单卡失败 → 该卡 `status='error'`,其他正常 | 向后兼容契约:缺 `status` 视作 `'ok'` |
| 周一 09:00 | 无事 | 后台任务调用 Claude Haiku 生成周报 | APScheduler cron |

---

## Mandatory Reading

| Priority | File | Lines | Why |
|---|---|---|---|
| P0 | `server/server.py` | 1-143 | 配置加载、日志、Flask app 初始化模式 |
| P0 | `server/server.py` | 144-224 | 数据模型 / `init_db` / `login_required` 装饰器 |
| P0 | `server/server.py` | 234-282 | `/report` 端点 —— ingest 集成点 |
| P0 | `server/server.py` | 284-394 | `dashboard()` 视图 —— 了解 `client_realtime_data` 形状 |
| P0 | `client/client.py` | 82-113 | `get_nvidia_gpu_info` —— bug 现场,需重写 |
| P0 | `client/client.py` | 115-211 | `get_system_info` 和数据契约 |
| P0 | `server/templates/dashboard.html` | 267-361 | GPU 循环,需加护栏 |
| P0 | `server/templates/settings.html` | 1-80 | 管理员页面 navbar + flash 模板,`/gpu-report` 会镜像这个结构 |
| P1 | `server/templates/announcements.html` | 1-175 | 含表格、表单、badge 的管理员页面范例 |
| P1 | `server/templates/dashboard.html` | 10-121 | CSS 风格(卡片、progress、徽章),新页面复用 |
| P1 | `server/templates/dashboard.html` | 365-387 | 30 天 uptime 历史条 —— 同为"日/小时网格",实现模式类似 |
| P2 | `docs/superpowers/specs/2026-04-24-gpu-usage-report-and-alerts-design.md` | all | spec 本身,16 节,所有细节都在 |
| P2 | `docs/superpowers/plans/2026-03-16-omni-status-fixes.md` | all | 历史 plan 文件,参考文风 |

## External Documentation

| Topic | Source | Key Takeaway |
|---|---|---|
| APScheduler + Flask | `/apscheduler/apscheduler` | `BackgroundScheduler(timezone=tz)`,`add_job(func, 'cron', ...)`;Flask 集成在 `app_context` 下运行 |
| Anthropic SDK prompt caching | `/anthropics/anthropic-sdk-python` | system 消息用 `{"type":"text","text":..., "cache_control":{"type":"ephemeral"}}` 启用缓存 |
| tzlocal | `/regebro/tzlocal` | `get_localzone()` 返回 `zoneinfo.ZoneInfo`,可直接喂给 APScheduler |
| bleach allowed tags | `bleach` docs | `bleach.clean(html, tags=[...], strip=True)` 剥离不在白名单的标签 |
| markdown extensions | `python-markdown` docs | `markdown.markdown(text, extensions=['extra'])` 支持表格、代码块 |
| Flask Blueprint | `/pallets/flask` | `Blueprint('gpu_report', __name__, url_prefix='/gpu-report', template_folder='templates')` |

---

## Patterns to Mirror

### NAMING_CONVENTION
```python
# SOURCE: server/server.py:157-183
class Client(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    hostname = db.Column(db.String(100))
    last_seen = db.Column(db.DateTime)

class UptimeRecord(db.Model):
    """每日在线状态快照,用于历史可用性展示"""
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(36), db.ForeignKey('client.id', ondelete='CASCADE'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    status = db.Column(db.Integer, default=0)
    __table_args__ = (db.UniqueConstraint('client_id', 'date', name='uq_uptime_client_date'),)
```
- PascalCase 类名;snake_case 列名;`__table_args__` 存 `UniqueConstraint` 和 `Index`;中文 docstring;FK 用 `ondelete='CASCADE'`。

### ERROR_HANDLING
```python
# SOURCE: server/server.py:58-62
if os.path.exists(config_file):
    try:
        config.read(config_file)
        ...
    except Exception as e:
        logger.error(f"加载配置文件失败: {e}")

logger.warning("使用默认配置")
return default_config
```
- `try/except Exception as e` + `logger.error(f"中文描述: {e}")` 然后 fallback。

### LOGGING_PATTERN
```python
# SOURCE: server/server.py:22-25
_log_handler = RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=5)
_log_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logging.basicConfig(level=logging.INFO, handlers=[_log_handler])
logger = logging.getLogger('system_monitor_server')
```
- 单个全局 logger,名字用下划线命名;新模块用同一个 logger(`logging.getLogger('system_monitor_server')`)。

### LOGIN_REQUIRED_DECORATOR
```python
# SOURCE: server/server.py:226-232
def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function
```
- 新的 `/gpu-report` 路由直接复用 `from server import login_required`(或把它挪到一个 `auth.py` 共享模块)。

### FLASH_PATTERN
```python
# SOURCE: server/server.py:483-484
flash('客户端信息已更新', 'success')
return redirect(url_for('dashboard'))
```
```html
<!-- SOURCE: server/templates/settings.html:71-79 -->
{% with messages = get_flashed_messages(with_categories=true) %}
  {% if messages %}
    {% for category, message in messages %}
      <div class="alert alert-{{ category }}" role="alert">
        {{ message }}
      </div>
    {% endfor %}
  {% endif %}
{% endwith %}
```
- 分类:`'success'` / `'danger'` / `'warning'` / `'info'`;模板顶部渲染。

### TEMPLATE_NAVBAR
```html
<!-- SOURCE: server/templates/settings.html:52-65 -->
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
```
- Bootstrap 5.1.3 CDN + Bootstrap Icons 1.8.1;bi 图标类名形式 `bi bi-<name>`。

### CARD_STYLING
```css
/* SOURCE: server/templates/dashboard.html:13-23 */
.card {
    margin-bottom: 20px;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
    border-radius: 12px;
    transition: all 0.3s ease;
    border: none;
}
```

### PROGRESS_COLOR_BY_THRESHOLD
```jinja
{# SOURCE: server/templates/dashboard.html:230 #}
{% set cpu_color = "bg-success" if client.cpu.usage_percent < 50 else ("bg-warning" if client.cpu.usage_percent < 80 else "bg-danger") %}
<div class="progress-bar {{ cpu_color }}" role="progressbar"
     style="width: {{ client.cpu.usage_percent }}%;" ...>
</div>
```
- GPU 报告的进度条用同样三档式颜色判断(绿/黄/红)。

### HEATMAP_LIKE_GRID
```jinja
{# SOURCE: server/templates/dashboard.html:376-385 #}
<div style="display:flex; gap:2px;">
  {% for day in client.uptime_history %}
    {% if day.status == 0 %}{% set bar_c = '#198754' %}
    {% elif day.status == 2 %}{% set bar_c = '#dc3545' %}
    {% else %}{% set bar_c = '#dee2e6' %}{% endif %}
    <div style="flex:1; height:18px; background-color:{{ bar_c }}; border-radius:2px;"
         title="{{ day.date }}: ...">
    </div>
  {% endfor %}
</div>
```
- 新热力图:168 个 `<div>` 替换 30 个 `<div>`,颜色判断从 3 档换成 4 档,title 加详细 tooltip。

### CONFIG_LOADER
```python
# SOURCE: server/server.py:31-62
def load_config():
    config = configparser.ConfigParser()
    config_file = '/etc/system-monitor/server/server.conf'
    default_config = {'host': '0.0.0.0', 'port': 5000, ...}
    if os.path.exists(config_file):
        try:
            config.read(config_file)
            server_config = config['server'] if 'server' in config else {}
            ...
            return {...}
        except Exception as e:
            logger.error(f"加载配置文件失败: {e}")
    logger.warning("使用默认配置")
    return default_config
```
- 新增 `load_gpu_report_config()` 读取 `[gpu_report]` 段,同一风格。

### CLIENT_SUBPROCESS_WITH_TIMEOUT
```python
# SOURCE: client/client.py:89-94
result = subprocess.run(
    ['nvidia-smi', ...],
    capture_output=True, text=True, check=True, timeout=5
)
```
- 保留,不改;只修改输出解析。

### INIT_DB_IDEMPOTENT
```python
# SOURCE: server/server.py:203-223
def init_db():
    db.create_all()
    try:
        with db.engine.connect() as conn:
            conn.execute(db.text('ALTER TABLE client ADD COLUMN display_order INTEGER DEFAULT 0'))
            conn.commit()
    except Exception:
        pass  # 如果列已存在则忽略错误
    ...
```
- 新表用 `db.create_all()` 自动创建,不需要 ALTER(是新表)。

### CLIENT_ID_FILE_LOCATION
```python
# SOURCE: client/client.py:18-20
CONFIG_FILE = '/etc/system-monitor/client.conf'
CLIENT_ID_FILE = '/etc/system-monitor/.client_id'
LOG_FILE = '/var/log/system-monitor/client.log'
```
- 系统级路径,已有约定,不变动。

### TEMPLATE_NO_DATA_FALLBACK
```html
<!-- SOURCE: server/templates/dashboard.html:181-185 -->
{% if not clients %}
<div class="alert alert-info text-center">
    <h4>当前没有连接的客户端</h4>
    <p>请在客户端机器上启动监控脚本</p>
</div>
{% else %}
...
```
- `/gpu-report` 空数据时同样用 alert-info 提示。

---

## Files to Change

| File | Action | Justification |
|---|---|---|
| `server/gpu_report.py` | CREATE | Blueprint + 模型 + ingest + 视图 + LLM agent 全部集中 |
| `server/templates/gpu_report.html` | CREATE | 报告主页面 |
| `server/templates/_gpu_report_history.html` | CREATE | 历史摘要子模板(Collapse 展开) |
| `server/server.py` | UPDATE | 注册 blueprint;`/report` 末尾调 `ingest_hourly_sample`;启动 scheduler;`init_db` 里创建新表 |
| `server/templates/dashboard.html` | UPDATE | GPU 循环加 `status` 护栏;坏卡单独 card;均值跳过 error 项 |
| `client/client.py` | UPDATE | `get_nvidia_gpu_info` 按行独立容错,加 `status` 字段 |
| `server/requirements.txt` | UPDATE | 加 APScheduler, tzlocal, anthropic, markdown, bleach |
| `tests/__init__.py` | CREATE | 让 tests 成为 package |
| `tests/conftest.py` | CREATE | pytest fixture:临时 sqlite db + Flask test client |
| `tests/test_gpu_hourly_ingest.py` | CREATE | 单元测试聚合逻辑 |
| `tests/test_gpu_report_cleanup.py` | CREATE | 保留策略测试 |
| `tests/test_report_endpoint.py` | CREATE | `/report` 集成测试,包括容错 |
| `tests/test_gpu_report_page.py` | CREATE | `/gpu-report` 页面 + API 测试 |
| `tests/test_client_gpu_parsing.py` | CREATE | 客户端 GPU 解析测试 |
| `tests/test_llm_summary.py` | CREATE | LLM agent 测试(mock anthropic) |
| `tests/test_dashboard_gpu_error_render.py` | CREATE | dashboard 坏卡渲染测试 |
| `pytest.ini` | CREATE | 测试配置(marker、coverage 阈值) |
| `README.md` | UPDATE | 新增报告页 + 配置说明段落 |

## NOT Building

- **独立告警通道**(邮件 / 微信 / Webhook)—— spec 第 2.2 节明确排除,所有警示内嵌报告页
- **占卡嫌疑检测**(VRAM 高 + util 低)—— 用户明确拒绝,避免误伤 LLM 部署
- **跨机器 GPU 调度器 / 任务分配 / 用户归属追踪**
- **Prometheus / InfluxDB / Grafana 接入**
- **实时 dashboard 的重构**(保持现有行为不变)
- **客户端二路上报端点** —— 沿用现有单端点 `/report`
- **多用户 / 权限分级** —— 仍是单一 `admin` 账户
- **前端 JS 框架 / SPA**(Chart.js 也不引入)—— 纯服务端模板 + CSS Grid
- **历史数据导出 / CSV 下载**(可以以后再做)

---

## Step-by-Step Tasks

任务按 spec 第 14 节的 6 阶段分组。每阶段结束都应该能独立 deploy + rollback。

### Phase 0 —— 测试基础设施

#### Task 0.1: 建立 tests/ 目录与 pytest 配置
- **ACTION**: 新建 `tests/__init__.py`、`tests/conftest.py`、`pytest.ini`;`server/requirements.txt` 加 `pytest`、`pytest-cov`、`pytest-flask`。
- **IMPLEMENT**:
  - `pytest.ini` 设置 `testpaths=tests`,markers `unit`/`integration`,`addopts = --cov=server --cov=client --cov-report=term-missing --cov-fail-under=80`
  - `conftest.py` 提供:
    - `app` fixture:创建 Flask app,用临时 `:memory:` sqlite DB,调 `init_db()`
    - `client` fixture:`app.test_client()`
    - `logged_in_client` fixture:`client.post('/login', ...)` 登录后的 client
    - `db_session` fixture:每测试回滚事务
- **MIRROR**: N/A(项目第一次加测试)
- **IMPORTS**: `pytest`, `flask`, `flask_sqlalchemy`
- **GOTCHA**: Flask-SQLAlchemy 需要 `app_context`,fixture 里 `with app.app_context(): yield`
- **VALIDATE**: `pytest --collect-only` 应该能发现测试,空跑不报错

#### Task 0.2: 将 server.py 改为可被 import 的模块
- **ACTION**: 把 `if __name__ == '__main__': ... app.run(...)` 放在 guarded 块,确保 `from server import app, db` 不会启动服务器
- **IMPLEMENT**: 已有 `if __name__ == '__main__':` 保护,核对 `init_db()` 调用也在保护里,否则 import 会尝试连数据库
- **MIRROR**: `server/server.py:650-655`
- **IMPORTS**: N/A
- **GOTCHA**: 目前 `with app.app_context(): init_db()` 在 guard 里,OK。但 `app = Flask(__name__)` 和 `db = SQLAlchemy(app)` 在模块顶层,测试中需要替换配置 —— 用 `app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'` 覆盖
- **VALIDATE**: `python -c "from server.server import app, db"` 不报错、不启动 server

---

### Phase 1 —— 客户端 bug 修复 + 契约变更

#### Task 1.1: 重写 `get_nvidia_gpu_info` 为按行独立容错
- **ACTION**: 拆分出 `_parse_gpu_line(i, line) -> dict`,失败返回 `status='error'` 样本;外层循环不再抛异常
- **IMPLEMENT**: 按 spec 第 6.2 节给出的 `_parse_gpu_line` 和 `get_nvidia_gpu_info` 代码替换 `client/client.py:82-113`
- **MIRROR**: 现有 `subprocess.run` 超时处理保留不变(CLIENT_SUBPROCESS_WITH_TIMEOUT 模式)
- **IMPORTS**: 已有的 `subprocess`, `logging`, `datetime.datetime`(在文件顶部已有)
- **GOTCHA**: 
  - `_nvidia_available` 语义要明确:**只在 `subprocess` 层面失败时置 False**(nvidia-smi 不可用),**不在解析失败时置 False**。这样能支持"nvidia-smi 存在但某些行报错"的场景
  - `status='error'` 样本必须包含 `index`、`name`(尽力从原始行解析,失败则 `f'GPU{i}'`)、`error`(原始行字符串)、`timestamp`
  - `status='ok'` 样本包含 `index`, `name`, `status`, `utilization`, `memory_used`, `memory_total`
- **VALIDATE**: 手工喂入包含 `[N/A]` 的 nvidia-smi stdout,断言返回的 list 长度正确、好卡 `status='ok'`、坏卡 `status='error'`

#### Task 1.2: 为客户端添加测试 `tests/test_client_gpu_parsing.py`
- **ACTION**: 覆盖所有解析路径
- **IMPLEMENT**: 用 `monkeypatch` mock `subprocess.run`,测试:
  - `test_parse_ok_line_returns_status_ok`
  - `test_parse_errored_line_returns_status_error`
  - `test_parse_mixed_ok_and_error_lines`(核心:GPU 1 坏,GPU 0 和 GPU 2 正常返回)
  - `test_parse_preserves_index_numbering`(GPU 1 是 error 时,GPU 2 的 index 仍然是 2,不是 1)
  - `test_parse_handles_all_errored_output`(全坏也不崩)
  - `test_nvidia_unavailable_when_binary_missing`(`FileNotFoundError` → 返回 `[]` 并锁 `_nvidia_available=False`)
  - `test_nvidia_parsing_error_does_not_lock_availability`(解析失败 ≠ 锁定)
- **MIRROR**: `tests/conftest.py` 的 monkeypatch 风格
- **IMPORTS**: `pytest`, `unittest.mock.patch`, `subprocess`
- **GOTCHA**: `_nvidia_available` 是模块级全局,每次测试前 reset 为 `None`(fixture `reset_nvidia_cache`)
- **VALIDATE**: `pytest tests/test_client_gpu_parsing.py -v` 全绿

#### Task 1.3: 冒烟验证客户端修复
- **ACTION**: 在一台实际有 GPU 的机器上(或 staging)跑客户端,人工模拟错误(如 `nvidia-smi` 输出里加 `[N/A]` 行)
- **IMPLEMENT**: 临时 wrapper 脚本伪造 nvidia-smi 输出,观察 `/var/log/system-monitor/client.log` 是否正常上报,服务器 last_seen 更新
- **MIRROR**: N/A
- **IMPORTS**: N/A
- **GOTCHA**: 无 GPU 机器上跑不了真实测试,只靠单元测试
- **VALIDATE**: 检查 dashboard 整机状态保持在线

---

### Phase 2 —— 数据模型 + ingest 逻辑

#### Task 2.1: 在 `server/gpu_report.py` 定义 `GpuHourlyUsage` 和 `LlmReport` 模型
- **ACTION**: 新建模块,从 `server.server import db` 复用 SQLAlchemy 实例;按 spec 4.1 / 4.2 定义模型
- **IMPLEMENT**:
```python
# server/gpu_report.py
from server.server import db
from datetime import datetime

class GpuHourlyUsage(db.Model):
    __tablename__ = 'gpu_hourly_usage'
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(36), db.ForeignKey('client.id', ondelete='CASCADE'), nullable=False)
    gpu_index = db.Column(db.Integer, nullable=False)
    hour = db.Column(db.DateTime, nullable=False)
    gpu_name = db.Column(db.String(100))
    vram_pct_avg = db.Column(db.Float, default=0.0)
    vram_pct_peak = db.Column(db.Float, default=0.0)
    util_pct_avg = db.Column(db.Float, default=0.0)
    util_pct_peak = db.Column(db.Float, default=0.0)
    ok_sample_count = db.Column(db.Integer, default=0)
    error_count = db.Column(db.Integer, default=0)
    __table_args__ = (
        db.UniqueConstraint('client_id', 'gpu_index', 'hour', name='uq_gpu_hourly'),
        db.Index('ix_gpu_hourly_hour', 'hour'),
    )

class LlmReport(db.Model):
    __tablename__ = 'llm_report'
    id = db.Column(db.Integer, primary_key=True)
    generated_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    period_start = db.Column(db.DateTime, nullable=False)
    period_end = db.Column(db.DateTime, nullable=False)
    model = db.Column(db.String(80))
    status = db.Column(db.String(20), default='ok')
    content = db.Column(db.Text)
    input_tokens = db.Column(db.Integer)
    output_tokens = db.Column(db.Integer)
    __table_args__ = (db.Index('ix_llm_report_generated_at', 'generated_at'),)
```
- **MIRROR**: NAMING_CONVENTION 的 `UptimeRecord` 模型
- **IMPORTS**: `from server.server import db`,`datetime`
- **GOTCHA**: 循环 import!`server.py` 也要 `from server.gpu_report import ...`。用**延迟 import**:`server.py` 里在 `init_db()` 内 `from server.gpu_report import GpuHourlyUsage, LlmReport` 触发表注册
- **VALIDATE**: 启动应用后 `.tables` in sqlite 应该能看到 `gpu_hourly_usage` 和 `llm_report`

#### Task 2.2: 实现 `ingest_hourly_sample`
- **ACTION**: 在 `server/gpu_report.py` 写增量均值 upsert
- **IMPLEMENT**: 按 spec 第 5.1 节代码实现
- **MIRROR**: `_record_uptime` at `server/server.py:192-200`(upsert 模式)
- **IMPORTS**: `from datetime import datetime`,`from server.server import db`,`logger` from server.py
- **GOTCHA**: 
  - 不在函数内 `db.session.commit()`,commit 留给外层 `/report` handler(与 `_record_uptime` 行为一致)
  - `gpu.get('status')` 为 `None`(旧客户端)时按 `'ok'` 处理(Section 6.5 向后兼容)
  - `memory_total <= 0` 计入 `error_count`,避免 division by zero
- **VALIDATE**: 单元测试(见 Task 2.4)

#### Task 2.3: 把 ingest 串进 `/report`
- **ACTION**: 修改 `server/server.py:234-282`,在 `db.session.commit()` 前加 ingest 循环,包 try/except
- **IMPLEMENT**:
```python
# server/server.py 的 /report handler 里
_record_uptime(data['client_id'], data)

try:
    from server.gpu_report import ingest_hourly_sample
    for gpu in data.get('gpu', []):
        ingest_hourly_sample(data['client_id'], gpu, datetime.now())
except Exception as e:
    logger.warning(f"GPU 小时样本写入失败: {e}")

db.session.commit()
```
- **MIRROR**: `_record_uptime` 调用位置 `server/server.py:274`
- **IMPORTS**: 延迟 import(避免循环)
- **GOTCHA**: 如果 `ingest_hourly_sample` 抛异常,`db.session` 可能进入 broken state,`commit()` 会失败。需要在 except 里 `db.session.rollback()` 后再 `db.session.commit()` 的 uptime 写入 —— 或者把 uptime 的 commit 提前。**首选方案**:把 ingest 放到 `_record_uptime` 的 commit 之后(单独 commit),失败时 rollback 不影响前面已提交的 uptime
- **VALIDATE**: `tests/test_report_endpoint.py::test_report_endpoint_ingests_hourly_sample` 通过;`test_report_endpoint_tolerates_ingest_failure` 通过(monkeypatch 让 ingest 抛异常,response 仍然 200 且 dashboard 实时数据正确)

#### Task 2.4: 单元测试 `tests/test_gpu_hourly_ingest.py`
- **ACTION**: 覆盖所有 ingest 分支
- **IMPLEMENT**:
  - `test_ingest_ok_sample_creates_row`:空表 → ingest 一次 → 表中 1 行,`ok_sample_count=1`,`error_count=0`,`vram_pct_avg` 等于输入
  - `test_ingest_ok_sample_updates_existing_row`:ingest 两次 → 1 行,`ok_sample_count=2`,`vram_pct_avg` 是均值
  - `test_ingest_errored_sample_increments_error_count`:ingest 一次 error → 1 行,`error_count=1`,`ok_sample_count=0`,均值为 0
  - `test_ingest_errored_sample_does_not_touch_averages`:先 ok 一次(avg=50),再 error 一次 → avg 仍是 50
  - `test_ingest_running_average_converges`:ingest 60 个样本 [10,20,...,600/60=10..90],断言 `abs(row.vram_pct_avg - expected_mean) < 0.01`
  - `test_ingest_peak_tracking`:ingest [30, 80, 50] → peak=80
  - `test_ingest_division_by_zero_memory_total_treated_as_error`:`memory_total=0` → `error_count` 增
  - `test_hour_bucket_truncation_boundary`:`datetime(2026,4,24,14,59,59)` 和 `(14,00,00)` 都映射到 `(14,00,00)`;`(15,00,00)` 映射到自己
  - `test_ingest_missing_status_treated_as_ok`:gpu dict 不带 `status` 字段,走 ok 路径(向后兼容)
  - `test_ingest_gpu_name_updates_on_each_call`:改 name → row.gpu_name 更新为新值
- **MIRROR**: AAA 模式(见 common/testing.md)
- **IMPORTS**: `pytest`, `datetime`
- **GOTCHA**: 每个测试用 `db_session` fixture,断言后 rollback
- **VALIDATE**: `pytest tests/test_gpu_hourly_ingest.py -v` 全绿;coverage `server/gpu_report.py::ingest_hourly_sample` ≥ 95%

---

### Phase 3 —— Dashboard 卡级别错误渲染

#### Task 3.1: 服务端计算 `gpu_last_ok` 字典
- **ACTION**: `/report` 中为每张 `status='ok'` GPU 记录 `last_ok` 时间
- **IMPLEMENT**: 在 `client_realtime_data[client_id]` 结构里加子 dict:
```python
# server/server.py 的 /report 里
rt = client_realtime_data.setdefault(data['client_id'], {})
rt_gpu_last_ok = rt.setdefault('gpu_last_ok', {})
for gpu in data.get('gpu', []):
    if gpu.get('status', 'ok') != 'error':
        rt_gpu_last_ok[gpu['index']] = datetime.now()

client_realtime_data[data['client_id']] = {
    'timestamp': datetime.fromisoformat(data['timestamp']),
    'cpu': data['cpu'],
    ...
    'gpu': data['gpu'],
    'gpu_last_ok': rt_gpu_last_ok,
    ...
}
```
- **MIRROR**: 现有 `client_realtime_data[data['client_id']] = {...}` 赋值模式
- **IMPORTS**: N/A
- **GOTCHA**: 注意**先读旧 `gpu_last_ok` 再覆盖整个 dict** 的顺序 —— 当前代码直接赋值会丢掉旧值;需要 `existing = client_realtime_data.get(data['client_id'], {})`,合并后覆盖
- **VALIDATE**: 测试 `/report` 调用两次,第二次一个 GPU 是 error,断言 `gpu_last_ok[gpu_idx]` 仍然是第一次的时间

#### Task 3.2: dashboard 视图把 `gpu_last_ok` 传给模板
- **ACTION**: 修改 `server/server.py:284-394` `dashboard()`,把每个 gpu 项标注 `last_ok_minutes_ago`
- **IMPLEMENT**:
```python
# dashboard() 里 client_data 构建时
now = datetime.now()
gpu_list = []
for gpu in realtime_data.get('gpu', []):
    g = dict(gpu)
    if g.get('status') == 'error':
        last_ok = realtime_data.get('gpu_last_ok', {}).get(g['index'])
        if last_ok:
            g['last_ok_minutes_ago'] = int((now - last_ok).total_seconds() // 60)
        else:
            g['last_ok_minutes_ago'] = None
    gpu_list.append(g)
# 用 gpu_list 替换传给模板的 'gpu' 字段
```
- **MIRROR**: 同文件内 `uptime_str` 计算(`server/server.py:302-306`)
- **IMPORTS**: N/A(datetime 已 import)
- **GOTCHA**: 旧客户端没有 `status` 字段,gpu_list 原样通过;模板靠 `gpu.status != 'error'` 走 ok 路径
- **VALIDATE**: `tests/test_dashboard_gpu_error_render.py` 断言响应 HTML 包含预期的坏卡 block

#### Task 3.3: 修改 `dashboard.html` 模板 —— GPU 循环加护栏 + 错误 card
- **ACTION**: 改 `server/templates/dashboard.html:267-285`(顶部摘要 progress bar)和 `340-361`(详情)
- **IMPLEMENT**:
  - 顶部平均值计算:`{% for gpu in client.gpu if gpu.status != 'error' %}` 替换现有 `{% for gpu in client.gpu %}`。如果全部是 error,`client.gpu|length` 不适用;改用 `client.gpu|rejectattr('status','equalto','error')|list|length`
  - 详情区:保留 ok 卡渲染;error 卡用单独 block:
```jinja
{% for gpu in client.gpu %}
  {% if gpu.status == 'error' %}
    <div class="mt-2 p-2" style="background:#fef2f2;border:1px solid #fecaca;border-radius:6px;">
      <div class="small" style="color:#991b1b;">
        <i class="bi bi-exclamation-triangle"></i>
        <b>{{ gpu.name }}(idx {{ gpu.index }})</b> —— 硬件/驱动异常
      </div>
      <div class="small" style="color:#991b1b;font-family:monospace;">
        nvidia-smi: {{ gpu.error|e }}
      </div>
      {% if gpu.last_ok_minutes_ago is not none %}
      <div class="small text-muted">上次正常读数 {{ gpu.last_ok_minutes_ago }} 分钟前</div>
      {% endif %}
    </div>
  {% else %}
    {# 现有 ok 渲染 #}
  {% endif %}
{% endfor %}
```
- **MIRROR**: HEATMAP_LIKE_GRID 模式(内联 style + 颜色);`gpu.error|e` XSS 过滤(模仿 `{{ announcement.content|e|replace(...) }}` at `dashboard.html:172`)
- **IMPORTS**: N/A(Jinja)
- **GOTCHA**:
  - 平均值公式 `ns.total / client.gpu|length` 分母要改成只计入 ok 卡数,否则全坏时除以 0
  - `{% for gpu in client.gpu if ... %}` 是 Jinja 语法,不是 Python;test 一下
  - `gpu.error` 可能包含 `<` / `>`,必须 `|e`
- **VALIDATE**: 新增 jinja test:`test_dashboard_renders_error_gpu_card_without_breaking_average`

#### Task 3.4: `tests/test_dashboard_gpu_error_render.py`
- **ACTION**: 集成测试 dashboard 对 error 卡的渲染
- **IMPLEMENT**:
  - `test_dashboard_renders_ok_gpus_normally`:注入只有 ok 的 client,响应 HTML 包含 `gpu.name` 和 util %
  - `test_dashboard_renders_error_gpu_with_red_box`:注入带 error 的 client,HTML 包含 `硬件/驱动异常`
  - `test_dashboard_machine_online_when_gpu_errored`:注入 `last_seen=now` 且一张卡 error,HTML 中整机仍是 `online` status dot
  - `test_dashboard_average_ignores_errored_gpus`:3 张卡(2 ok util=50%/60%,1 error),平均显示 55%
  - `test_dashboard_survives_all_errored_gpus`(边界:全坏也不 500)
  - `test_dashboard_backward_compat_no_status_field`:gpu dict 里没有 `status`,走 ok 路径
- **MIRROR**: AAA
- **IMPORTS**: `pytest`, `flask.testing.FlaskClient`
- **GOTCHA**: 测试里直接填充 `server.server.client_realtime_data[client_id]` 绕过 /report
- **VALIDATE**: `pytest tests/test_dashboard_gpu_error_render.py -v`

---

### Phase 4 —— APScheduler 清理与调度

#### Task 4.1: 安装并初始化 APScheduler
- **ACTION**: `server/requirements.txt` 新增 `APScheduler>=3.10`、`tzlocal>=5.0`
- **IMPLEMENT**: 在 `server/gpu_report.py` 内:
```python
from apscheduler.schedulers.background import BackgroundScheduler
from tzlocal import get_localzone

_scheduler = None

def init_scheduler(app):
    global _scheduler
    if _scheduler is not None:
        return _scheduler
    cfg = app.config.get('GPU_REPORT', {})
    tz_name = cfg.get('timezone')
    tz = tz_name if tz_name else get_localzone()
    _scheduler = BackgroundScheduler(timezone=tz)
    _scheduler.add_job(lambda: _run_in_context(app, cleanup_hourly), 'cron', minute=5, id='cleanup_hourly')
    _scheduler.add_job(lambda: _run_in_context(app, cleanup_llm_reports), 'cron',
                       day_of_week='sun', hour=3, id='cleanup_llm')
    _scheduler.add_job(lambda: _run_in_context(app, generate_llm_summary), 'cron',
                       day_of_week='mon', hour=9, id='llm_summary')
    _scheduler.start()
    return _scheduler

def _run_in_context(app, func):
    with app.app_context():
        try:
            func()
        except Exception as e:
            logger.error(f"scheduled job {func.__name__} 失败: {e}")
```
- **MIRROR**: LOGGING_PATTERN(`logger.error` 带中文)
- **IMPORTS**: `apscheduler.schedulers.background`, `tzlocal`
- **GOTCHA**:
  - APScheduler job 需要 `app_context()` 才能用 `db.session`
  - 幂等性:`if _scheduler is not None: return`,避免 reload 重复
  - Flask 开发服务器默认 debug 会用 reloader,双起 scheduler —— 在 `if __name__ == '__main__':` 里只在非 reloader 子进程调用 `init_scheduler`(`os.environ.get('WERKZEUG_RUN_MAIN') == 'true'`)
- **VALIDATE**: 启动后 `curl -s localhost:5000/` 不崩,日志有 `APScheduler started`

#### Task 4.2: `cleanup_hourly` 和 `cleanup_llm_reports`
- **ACTION**: 实现两个清理函数
- **IMPLEMENT**:
```python
def cleanup_hourly():
    cfg = current_app.config['GPU_REPORT']
    cutoff = datetime.now() - timedelta(days=cfg['retention_days'])
    deleted = GpuHourlyUsage.query.filter(GpuHourlyUsage.hour < cutoff).delete()
    db.session.commit()
    logger.info(f"GPU 小时数据清理: 删除 {deleted} 行(早于 {cutoff})")

def cleanup_llm_reports():
    cfg = current_app.config['GPU_REPORT']
    keep = cfg.get('llm_report_retention', 12)
    ids_to_keep = [r.id for r in
                   LlmReport.query.order_by(LlmReport.generated_at.desc()).limit(keep).all()]
    deleted = LlmReport.query.filter(~LlmReport.id.in_(ids_to_keep)).delete(synchronize_session=False)
    db.session.commit()
    logger.info(f"LLM 摘要清理: 保留最近 {keep} 条,删除 {deleted} 条")
```
- **MIRROR**: ERROR_HANDLING 模式(log + continue)
- **IMPORTS**: `flask.current_app`, `datetime.timedelta`
- **GOTCHA**: `delete(synchronize_session=False)` 对 SQLite bulk delete 更快,但 ORM 缓存里的对象可能 stale —— 清理任务独立运行,不影响别的路径,可接受
- **VALIDATE**: `tests/test_gpu_report_cleanup.py`

#### Task 4.3: `tests/test_gpu_report_cleanup.py`
- **ACTION**: 覆盖保留与级联
- **IMPLEMENT**:
  - `test_cleanup_deletes_rows_older_than_7d`:建 10 行,5 行 8 天前,5 行今天 → cleanup 后 5 行
  - `test_cleanup_keeps_exactly_7d_boundary`:精确 7 天 − 1s 的保留;7 天 + 1s 删除
  - `test_cleanup_llm_reports_keeps_latest_12`:建 20 条 → 剩 12 条(按 `generated_at` desc)
  - `test_client_delete_cascades_gpu_hourly_usage`:删除 Client → 相关 `GpuHourlyUsage` 行自动删除(SQLite 需 PRAGMA foreign_keys=ON;see GOTCHA)
- **MIRROR**: AAA
- **IMPORTS**: `pytest`, `datetime`
- **GOTCHA**: **SQLite 默认不启用外键约束**。在 conftest.py `app` fixture 里:
```python
from sqlalchemy import event
@event.listens_for(db.engine, "connect")
def _fk_pragma_on_connect(dbapi_conn, _):
    dbapi_conn.execute("PRAGMA foreign_keys=ON")
```
- **VALIDATE**: `pytest tests/test_gpu_report_cleanup.py -v`

---

### Phase 5 —— `/gpu-report` 页面

#### Task 5.1: 定义 Blueprint 和配置加载
- **ACTION**: 在 `server/gpu_report.py` 注册 blueprint,路径前缀 `/gpu-report`
- **IMPLEMENT**:
```python
from flask import Blueprint, render_template, jsonify
from server.server import login_required, client_realtime_data

gpu_report_bp = Blueprint('gpu_report', __name__,
                          url_prefix='/gpu-report',
                          template_folder='templates')

def load_gpu_report_config(config_parser):
    section = config_parser['gpu_report'] if 'gpu_report' in config_parser else {}
    defaults = {
        'retention_days': 7,
        'idle_vram_threshold': 15,
        'heatmap_low_threshold': 20,
        'heatmap_high_threshold': 70,
        'longterm_vram_threshold': 20,
        'longterm_hours_required': 120,
        'llm_model': 'claude-haiku-4-5-20251001',
        'llm_schedule_cron': '0 9 * * 1',
        'llm_report_retention': 12,
        'timezone': '',
    }
    return {k: (type(v)(section[k]) if k in section and section[k] else v)
            for k, v in defaults.items()}
```
- **MIRROR**: CONFIG_LOADER(`load_config` at `server/server.py:31-62`)
- **IMPORTS**: `flask.Blueprint`
- **GOTCHA**:
  - `from server.server import login_required` 会触发循环 import。解决方案:**把 `login_required` 抽到 `server/auth.py` 共享模块**,`server.py` 和 `gpu_report.py` 都从那里 import。或者放在 `gpu_report.py` 顶部做**延迟 import**(在装饰器定义时导入)
  - 推荐:新建 `server/auth.py`,`from flask import session, redirect, url_for, request; import functools; def login_required(f): ...`
- **VALIDATE**: `curl localhost:5000/gpu-report` → 302 到 /login(未登录);登录后 200

#### Task 5.2: 实现 heatmap 查询函数
- **ACTION**: `server/gpu_report.py::get_heatmap_data(days=7)` 返回渲染所需的数据结构
- **IMPLEMENT**:
```python
def get_heatmap_data(days=7):
    now = datetime.now()
    hour_end = now.replace(minute=0, second=0, microsecond=0)
    hour_start = hour_end - timedelta(hours=days * 24)

    rows = (db.session.query(GpuHourlyUsage, Client.hostname)
            .join(Client, GpuHourlyUsage.client_id == Client.id)
            .filter(GpuHourlyUsage.hour >= hour_start)
            .filter(GpuHourlyUsage.hour < hour_end)
            .order_by(Client.display_order, GpuHourlyUsage.gpu_index, GpuHourlyUsage.hour)
            .all())

    # 按 (client_id, gpu_index) 分组,填充 168 小时稀疏矩阵
    grouped = {}
    for usage, hostname in rows:
        key = (usage.client_id, usage.gpu_index)
        bucket = grouped.setdefault(key, {
            'client_id': usage.client_id, 'hostname': hostname,
            'gpu_index': usage.gpu_index, 'gpu_name': usage.gpu_name,
            'cells_by_hour': {},
        })
        bucket['gpu_name'] = usage.gpu_name  # 最新值
        bucket['cells_by_hour'][usage.hour] = usage

    # 转换为 168 小时有序 cell 列表
    hours = [hour_start + timedelta(hours=i) for i in range(days * 24)]
    result = []
    for key, bucket in grouped.items():
        cells = []
        for h in hours:
            u = bucket['cells_by_hour'].get(h)
            if u is None or u.ok_sample_count == 0:
                cells.append({'hour': h, 'status': 'nodata',
                              'err': u.error_count if u else 0})
            else:
                cells.append({'hour': h, 'status': 'ok',
                              'vram_avg': round(u.vram_pct_avg, 1),
                              'util_avg': round(u.util_pct_avg, 1),
                              'vram_peak': round(u.vram_pct_peak, 1),
                              'ok': u.ok_sample_count, 'err': u.error_count})
        result.append({
            'hostname': bucket['hostname'], 'gpu_index': bucket['gpu_index'],
            'gpu_name': bucket['gpu_name'], 'cells': cells,
        })
    return {'hour_start': hour_start, 'hour_end': hour_end, 'rows': result}
```
- **MIRROR**: 现有 dashboard 里 30 天 uptime 循环(`server/server.py:374-388`)
- **IMPORTS**: `sqlalchemy.orm` 通过 `db.session.query`
- **GOTCHA**: 一次性 query 所有 row(6.7k 行)而不是 N+1;join `Client` 拿 hostname
- **VALIDATE**: 单元测试断言返回结构正确(168 cells/row)

#### Task 5.3: 实现"当前空闲 GPU"查询
- **ACTION**: `get_idle_gpus()` 结合实时内存 + 历史表
- **IMPLEMENT**:
```python
def get_idle_gpus():
    cfg = current_app.config['GPU_REPORT']
    threshold = cfg['idle_vram_threshold']
    now = datetime.now()

    # 一次性查出历史表里每卡最后一次非空闲小时(用于"已空闲 Xh")
    recent_hours = (db.session.query(
        GpuHourlyUsage.client_id, GpuHourlyUsage.gpu_index,
        db.func.max(GpuHourlyUsage.hour).label('last_busy')
    ).filter(GpuHourlyUsage.vram_pct_avg >= threshold)
     .group_by(GpuHourlyUsage.client_id, GpuHourlyUsage.gpu_index)
     .all())
    last_busy_map = {(r.client_id, r.gpu_index): r.last_busy for r in recent_hours}

    idle = []
    for client in Client.query.order_by(Client.display_order).all():
        rt = client_realtime_data.get(client.id)
        if not rt: continue
        # 只算在线客户端
        if (now - client.last_seen).total_seconds() >= 600: continue
        for gpu in rt.get('gpu', []):
            if gpu.get('status') == 'error': continue
            if gpu.get('memory_total', 0) <= 0: continue
            vram_pct = gpu['memory_used'] / gpu['memory_total'] * 100
            if vram_pct >= threshold: continue
            last_busy = last_busy_map.get((client.id, gpu['index']))
            if last_busy:
                idle_minutes = int((now - last_busy).total_seconds() // 60)
            else:
                idle_minutes = int((now - client.last_seen).total_seconds() // 60)
            idle.append({
                'hostname': client.hostname,
                'display_name': client.display_name or client.hostname,
                'gpu_index': gpu['index'], 'gpu_name': gpu.get('name', '?'),
                'vram_pct': round(vram_pct, 1),
                'idle_minutes': idle_minutes,
            })
    idle.sort(key=lambda x: -x['idle_minutes'])  # 空闲时间长的在前
    return idle
```
- **MIRROR**: CONFIG_LOADER;dashboard() 的在线判定 `(datetime.now() - client.last_seen).total_seconds() < 600`
- **IMPORTS**: `from server.server import client_realtime_data`
- **GOTCHA**: `client_realtime_data` 是 server.py 的全局 dict,跨模块 import 时必须 import 那个**引用**,不是值拷贝
- **VALIDATE**: `tests/test_gpu_report_page.py::test_idle_excludes_errored_gpus`

#### Task 5.4: 实现"长期空闲 GPU"查询
- **ACTION**: `get_longterm_idle()` 聚合 7 天数据
- **IMPLEMENT**:
```python
def get_longterm_idle():
    cfg = current_app.config['GPU_REPORT']
    vram_threshold = cfg['longterm_vram_threshold']
    hours_required = cfg['longterm_hours_required']
    now = datetime.now()
    period_start = now.replace(minute=0,second=0,microsecond=0) - timedelta(days=7)

    rows = (GpuHourlyUsage.query
            .filter(GpuHourlyUsage.hour >= period_start)
            .all())
    grouped = {}
    for r in rows:
        grouped.setdefault((r.client_id, r.gpu_index), []).append(r)

    result = []
    for (cid, gidx), row_list in grouped.items():
        # weighted avg by ok_sample_count
        total_ok = sum(r.ok_sample_count for r in row_list)
        if total_ok == 0: continue
        vram_avg = sum(r.vram_pct_avg * r.ok_sample_count for r in row_list) / total_ok
        util_avg = sum(r.util_pct_avg * r.ok_sample_count for r in row_list) / total_ok
        low_hours = sum(1 for r in row_list if r.ok_sample_count > 0 and r.vram_pct_avg < vram_threshold)

        if vram_avg >= vram_threshold: continue
        if low_hours < hours_required: continue

        client = Client.query.get(cid)
        if not client: continue
        result.append({
            'hostname': client.hostname,
            'display_name': client.display_name or client.hostname,
            'gpu_index': gidx,
            'gpu_name': row_list[-1].gpu_name,
            'vram_avg_7d': round(vram_avg, 1),
            'util_avg_7d': round(util_avg, 1),
            'low_hours': low_hours,
            'total_hours': len(row_list),
        })
    result.sort(key=lambda x: -x['low_hours'])
    return result
```
- **MIRROR**: get_heatmap_data 的 group-by 模式
- **IMPORTS**: N/A
- **GOTCHA**: `low_hours` 阈值用**同一个** `longterm_vram_threshold`(spec Section 8.2 ③ 的 `低占用小时`)
- **VALIDATE**: 单元测试

#### Task 5.5: 实现"硬件异常"查询
- **ACTION**: `get_error_gpus()`
- **IMPLEMENT**:
```python
def get_error_gpus():
    period_start = datetime.now() - timedelta(days=7)
    rows = (GpuHourlyUsage.query
            .filter(GpuHourlyUsage.hour >= period_start)
            .filter(GpuHourlyUsage.error_count > 0)
            .all())
    grouped = {}
    for r in rows:
        grouped.setdefault((r.client_id, r.gpu_index), []).append(r)

    result = []
    for (cid, gidx), rlist in grouped.items():
        client = Client.query.get(cid)
        if not client: continue
        total_err = sum(r.error_count for r in rlist)
        latest_row = max(rlist, key=lambda r: r.hour)
        rt = client_realtime_data.get(cid, {})
        latest_err_sample = next(
            (g for g in rt.get('gpu', [])
             if g.get('index') == gidx and g.get('status') == 'error'), None)
        result.append({
            'hostname': client.hostname,
            'gpu_index': gidx,
            'gpu_name': latest_row.gpu_name,
            'err_hours': len(rlist),
            'err_samples': total_err,
            'latest_error': (latest_err_sample or {}).get('error', ''),
        })
    result.sort(key=lambda x: -x['err_hours'])
    return result
```
- **MIRROR**: `get_longterm_idle` 结构
- **IMPORTS**: N/A
- **GOTCHA**: `latest_error` 可能为空(实时数据已清理);模板层渲染 fallback 到"见日志"
- **VALIDATE**: 单元测试

#### Task 5.6: 报告页视图函数
- **ACTION**: `server/gpu_report.py` 加路由
- **IMPLEMENT**:
```python
@gpu_report_bp.route('/')
@login_required
def report_page():
    latest_summary = (LlmReport.query
                      .filter_by(status='ok')
                      .order_by(LlmReport.generated_at.desc())
                      .first())
    latest_html = render_markdown_safe(latest_summary.content) if latest_summary else None
    history = (LlmReport.query
               .order_by(LlmReport.generated_at.desc())
               .limit(12).all())
    history_items = [
        {'generated_at': r.generated_at, 'status': r.status,
         'html': render_markdown_safe(r.content) if r.status == 'ok' else None,
         'error': r.content if r.status == 'error' else None}
        for r in history
    ]
    return render_template('gpu_report.html',
        summary_stats=get_summary_stats(),
        idle_gpus=get_idle_gpus(),
        heatmap=get_heatmap_data(days=7),
        longterm_idle=get_longterm_idle(),
        error_gpus=get_error_gpus(),
        latest_summary=latest_summary,
        latest_summary_html=latest_html,
        history=history_items,
    )

@gpu_report_bp.route('/api/heatmap.json')
@login_required
def api_heatmap():
    data = get_heatmap_data(days=int(request.args.get('days', 7)))
    # serialize datetime
    data['hour_start'] = data['hour_start'].isoformat()
    data['hour_end'] = data['hour_end'].isoformat()
    for row in data['rows']:
        for cell in row['cells']:
            cell['hour'] = cell['hour'].isoformat()
    return jsonify(data)

@gpu_report_bp.route('/api/idle.json')
@login_required
def api_idle():
    return jsonify({'timestamp': datetime.now().isoformat(),
                    'idle_gpus': get_idle_gpus()})
```
- **MIRROR**: `server.py` 现有 route 模式(`@app.route`, `@login_required`, `render_template`)
- **IMPORTS**: `flask.request`, `render_template`, `jsonify`
- **GOTCHA**: 
  - `get_summary_stats()` 待实现:`{'total_clients': ..., 'online_clients': ..., 'total_gpus': ..., 'idle_count': ..., 'error_count': ...}`
  - `render_markdown_safe` 见 Phase 6
- **VALIDATE**: `tests/test_gpu_report_page.py`

#### Task 5.7: 编写 `templates/gpu_report.html`
- **ACTION**: 完整 HTML 模板,镜像 settings.html 的 navbar 和 flash 模式
- **IMPLEMENT**:
  - Head:CDN Bootstrap 5.1.3 + Bootstrap Icons 1.8.1 + 内联 CSS(卡片、grid、heatmap 颜色)
  - Navbar:与 settings.html 一致
  - 顶部摘要:4 个 Bootstrap col 小卡片
  - LLM 摘要块:`{{ latest_summary_html|safe }}`(已通过 bleach 消毒)+ `[查看历史]` Collapse
  - Section ①:网格 row,每个 idle GPU 一个 `col-md-4` 卡片
  - Section ②:`<table>` 每行 GPU,168 个 `<div>` 细胞 + title tooltip
  - Section ③ / ④:`<table class="table table-sm">`
- **MIRROR**: 
  - TEMPLATE_NAVBAR(settings.html)
  - CARD_STYLING(dashboard.html)
  - HEATMAP_LIKE_GRID(dashboard.html:376-385)
- **IMPORTS**: N/A
- **GOTCHA**:
  - heatmap cell `title` 用中文,含空格/中英文混合需 HTML 实体
  - Collapse(Bootstrap)需要 JS bundle,navbar 下已引入
- **VALIDATE**: 打开页面 visually check

#### Task 5.8: `tests/test_gpu_report_page.py`
- **ACTION**: 端到端路由测试
- **IMPLEMENT**:
  - `test_gpu_report_requires_login`:未登录 GET → 302
  - `test_gpu_report_empty_renders_no_data_message`:空 db → 200,包含 "暂无数据"
  - `test_gpu_report_renders_heatmap_with_data`:插入 7 天 sample,GET → 响应 HTML 含 hostname 和 168 cells
  - `test_gpu_report_idle_section_shows_idle_gpus`:塞 client_realtime_data,VRAM<15% → 该 gpu 出现在 idle section
  - `test_gpu_report_longterm_idle_threshold`:阈值边界
  - `test_gpu_report_error_section_lists_errored_gpus`
  - `test_api_heatmap_json_structure`:GET `/gpu-report/api/heatmap.json?days=7` → 200 JSON,含 `rows[0].cells` 长度 168
  - `test_api_idle_json_excludes_offline_clients`
- **MIRROR**: AAA, fixture
- **IMPORTS**: `pytest`, `json`, `datetime`
- **VALIDATE**: `pytest tests/test_gpu_report_page.py -v`

#### Task 5.9: 在 dashboard navbar 加 "GPU 报告" 链接
- **ACTION**: 改 `server/templates/dashboard.html` admin 侧的 btn-group,加一个按钮
- **IMPLEMENT**:
```html
<!-- 在 {% if is_admin %} 块里 -->
<a href="{{ url_for('gpu_report.report_page') }}" class="btn btn-sm btn-outline-light" title="GPU 报告">
    <i class="bi bi-bar-chart-line"></i>
    <span class="d-none d-md-inline ms-1">GPU 报告</span>
</a>
```
- **MIRROR**: `dashboard.html:135-151` 其他 btn-group 按钮
- **IMPORTS**: N/A
- **GOTCHA**: url_for 用 blueprint 前缀 `gpu_report.report_page`
- **VALIDATE**: 登录后 dashboard 能看到新按钮,点击可跳转

---

### Phase 6 —— LLM 摘要 agent

#### Task 6.1: `server/requirements.txt` 加依赖
- **ACTION**: 添加 `anthropic>=0.40`, `markdown>=3.5`, `bleach>=6.0`
- **VALIDATE**: `pip install -r server/requirements.txt` 成功

#### Task 6.2: 实现 `build_llm_payload`
- **ACTION**: 按 spec 9.2 节代码(已更新为去 `_MAX_GPU_INDEX`)
- **IMPLEMENT**: 见 spec 9.2
- **MIRROR**: `get_longterm_idle` 的 group-by + weighted avg 套路
- **IMPORTS**: N/A
- **GOTCHA**: Payload 应该 < 2000 tokens(Claude SDK 粗估:JSON 字符串长度 / 3.5)。unit test 断言
- **VALIDATE**: `tests/test_llm_summary.py::test_build_llm_payload_token_budget_under_2000`

#### Task 6.3: 实现 `generate_llm_summary`
- **ACTION**: 调用 Claude API,处理重试
- **IMPLEMENT**:
```python
import anthropic
_SYSTEM_PROMPT = """你是实验室 GPU 资源使用情况的分析助手。..."""  # Section 9.3

def generate_llm_summary():
    api_key = os.environ.get('ANTHROPIC_API_KEY')
    if not api_key:
        logger.warning("ANTHROPIC_API_KEY 未设置,跳过 LLM 摘要")
        return
    cfg = current_app.config['GPU_REPORT']
    payload = build_llm_payload(datetime.now(), cfg)
    client = anthropic.Anthropic(api_key=api_key)

    last_err = None
    for attempt in range(3):
        try:
            resp = client.messages.create(
                model=cfg['llm_model'],
                max_tokens=800,
                system=[{
                    "type": "text",
                    "text": _SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }],
                messages=[{"role": "user",
                           "content": f"请分析以下过去一周的 GPU 使用数据,生成中文周报。\n\n数据:\n{json.dumps(payload, ensure_ascii=False, indent=2)}"}],
                timeout=30,
            )
            content = "".join(b.text for b in resp.content if b.type == 'text')
            db.session.add(LlmReport(
                generated_at=datetime.now(),
                period_start=datetime.fromisoformat(payload['period'].split(' ~ ')[0]),
                period_end=datetime.fromisoformat(payload['period'].split(' ~ ')[1]),
                model=cfg['llm_model'],
                status='ok',
                content=content,
                input_tokens=resp.usage.input_tokens,
                output_tokens=resp.usage.output_tokens,
            ))
            db.session.commit()
            logger.info(f"LLM 周报生成成功, {resp.usage.input_tokens}in/{resp.usage.output_tokens}out")
            return
        except Exception as e:
            last_err = e
            logger.warning(f"LLM 调用第 {attempt+1} 次失败: {e}")
            if attempt < 2:
                time.sleep([60, 300][attempt])

    db.session.add(LlmReport(
        generated_at=datetime.now(),
        period_start=datetime.now() - timedelta(days=7),
        period_end=datetime.now(),
        model=cfg['llm_model'], status='error',
        content=f"{type(last_err).__name__}: {last_err}",
    ))
    db.session.commit()
    logger.error(f"LLM 周报生成全部失败: {last_err}")
```
- **MIRROR**: ERROR_HANDLING(log + fallback)
- **IMPORTS**: `anthropic`, `json`, `time`, `os`, `flask.current_app`
- **GOTCHA**:
  - `period` 字段用 ISO date 好解析,不是 "YYYY-MM-DD ~ YYYY-MM-DD" —— 调整 `build_llm_payload` 输出或用 `period_start`/`period_end` 分开字段
  - Anthropic SDK 的 `client.messages.create(..., system=[...])` 是 1.0+ 的签名;确认版本
  - prompt caching 需要 system 超过 1024 tokens 才触发缓存,否则无差别
- **VALIDATE**: `tests/test_llm_summary.py` 用 mock anthropic

#### Task 6.4: 实现 `render_markdown_safe`
- **ACTION**: spec 9.5 管线
- **IMPLEMENT**: spec 9.5 代码
- **MIRROR**: N/A
- **IMPORTS**: `markdown`, `bleach`
- **GOTCHA**: 白名单不含 `<a>`(避免 LLM 生成钓鱼链接),如果需要再按需加
- **VALIDATE**: `test_llm_report_html_rendering_escapes_xss`

#### Task 6.5: `tests/test_llm_summary.py`
- **ACTION**: mock anthropic SDK,覆盖成功/失败/无 key
- **IMPLEMENT**:
  - `test_build_llm_payload_token_budget_under_2000`
  - `test_build_llm_payload_excludes_clients_with_no_data`
  - `test_build_llm_payload_uses_actual_gpu_indices`(不依赖 `_MAX_GPU_INDEX`)
  - `test_weighted_avg_computation`
  - `test_llm_summary_success_writes_report_row`:mock `anthropic.Anthropic` 返回固定 content,断言 db 里有 `status='ok'` 的 row
  - `test_llm_summary_api_failure_writes_error_row_after_retries`:mock 三次抛异常,断言 `status='error'`,最终 commit 成功
  - `test_llm_summary_missing_api_key_skips_gracefully`:`monkeypatch.delenv('ANTHROPIC_API_KEY')`,函数返回 None,db 无新 row
  - `test_render_markdown_safe_escapes_script_tag`:输入 `<script>alert(1)</script>` 必须被剥离
  - `test_render_markdown_safe_preserves_allowed_tags`:`**粗体**` → `<strong>`
- **MIRROR**: AAA
- **IMPORTS**: `pytest`, `unittest.mock`
- **GOTCHA**: `anthropic.Anthropic` 构造函数不触发 HTTP,mock `client.messages.create` 即可
- **VALIDATE**: `pytest tests/test_llm_summary.py -v`

#### Task 6.6: 在 `gpu_report.html` 渲染 LLM 摘要块
- **ACTION**: Task 5.7 已经有 placeholder;此处补全渲染与历史 Collapse
- **IMPLEMENT**:
```jinja
<div class="card mb-4">
  <div class="card-header d-flex justify-content-between align-items-center">
    <h5 class="mb-0"><i class="bi bi-robot"></i> 本周 AI 摘要</h5>
    <div>
      {% if latest_summary %}
      <small class="text-muted">
        生成于 {{ latest_summary.generated_at.strftime('%Y-%m-%d %H:%M') }}
      </small>
      <a class="btn btn-sm btn-outline-secondary ms-2" data-bs-toggle="collapse" href="#summary-history">
        查看历史
      </a>
      {% endif %}
    </div>
  </div>
  <div class="card-body">
    {% if latest_summary_html %}
      {{ latest_summary_html|safe }}
    {% elif latest_summary and latest_summary.status == 'error' %}
      <div class="alert alert-warning mb-0">
        <i class="bi bi-exclamation-triangle"></i>
        上次摘要生成失败,详情见日志。下一次运行:下周一 09:00。
      </div>
    {% else %}
      <div class="alert alert-info mb-0">
        <i class="bi bi-info-circle"></i>
        尚未生成任何摘要。首次运行:下个周一 09:00(或未配置 ANTHROPIC_API_KEY)。
      </div>
    {% endif %}
  </div>
  <div class="collapse" id="summary-history">
    <div class="card-body border-top">
      <h6>历史摘要(最近 12 条)</h6>
      {% for item in history %}
        <div class="mb-3 pb-3 border-bottom">
          <small class="text-muted">{{ item.generated_at.strftime('%Y-%m-%d %H:%M') }}</small>
          {% if item.html %}{{ item.html|safe }}
          {% else %}<div class="text-danger small">生成失败: {{ item.error }}</div>
          {% endif %}
        </div>
      {% endfor %}
    </div>
  </div>
</div>
```
- **MIRROR**: dashboard.html 的 Collapse 用法;announcements.html 的 card/card-header 模式
- **IMPORTS**: N/A
- **GOTCHA**: `{{ html|safe }}` 只能放 **已经过 bleach** 的内容
- **VALIDATE**: 手工插一条 `LlmReport(status='ok', content='**测试**')` → 页面显示粗体"测试"

---

### Phase 7 —— 集成、文档、收尾

#### Task 7.1: 在 `server/server.py` 注册 blueprint 与 scheduler
- **ACTION**: 修改 `app = Flask(__name__)` 之后,加:
- **IMPLEMENT**:
```python
# server/server.py
from server.gpu_report import gpu_report_bp, init_scheduler, load_gpu_report_config

app.register_blueprint(gpu_report_bp)

# load_config() 之后
app.config['GPU_REPORT'] = load_gpu_report_config(configparser_instance)

# if __name__ == '__main__' 块里,init_db 之后
with app.app_context():
    init_db()
if os.environ.get('WERKZEUG_RUN_MAIN') == 'true' or not app.debug:
    init_scheduler(app)
```
- **MIRROR**: N/A(新模式)
- **IMPORTS**: `from server.gpu_report import ...`
- **GOTCHA**: `load_config` 现在返回 dict,而不是 configparser 对象。需要把 `load_gpu_report_config` 参数改成接受 configparser object,并且在 `load_config` 里同时读 `server` 和 `gpu_report` 段 —— 或者分两次读文件
- **VALIDATE**: 启动成功;`curl localhost:5000/gpu-report` 正常

#### Task 7.2: 更新 README.md
- **ACTION**: 新增 "GPU 使用报告" 和 "配置" 段
- **IMPLEMENT**:
  - 描述 `/gpu-report` 页面功能
  - 列出环境变量(`ANTHROPIC_API_KEY` 可选)
  - 列出 `[gpu_report]` 配置项
- **MIRROR**: 现有 README.md 风格
- **IMPORTS**: N/A
- **GOTCHA**: 不要 leak 任何 secret 示例
- **VALIDATE**: 人工阅读

#### Task 7.3: Coverage 达标检查
- **ACTION**: 运行全部测试,确认 `--cov-fail-under=80` 通过
- **IMPLEMENT**:
```bash
cd /home/phaedrus/aimlab/omni-status
pytest --cov=server --cov=client --cov-report=term-missing
```
- **VALIDATE**: 总 coverage ≥ 80%,`server/gpu_report.py` ≥ 90%,`client/client.py` 的 GPU 解析路径 ≥ 90%

#### Task 7.4: 手工冒烟
- **ACTION**: 按 spec 14 节各阶段的 "独立可部署" 标准验证
- **IMPLEMENT**:
  1. 启动 server 观察日志无 ERROR
  2. 一个客户端正常上报 → dashboard 正常
  3. 临时破坏一个客户端的 nvidia-smi 输出 → dashboard 单卡红框 + 整机在线
  4. 登录 admin → 访问 `/gpu-report` → 顶部摘要、idle 区、heatmap(至少展示几个小时的格子)、长期空闲空表 OK、异常表有一行
  5. 手工触发 `generate_llm_summary()`(直接 REPL 调用)→ 页面显示 AI 摘要
  6. 手工 advance 时间模拟 7 天后 → 清理任务把旧数据删掉
- **VALIDATE**: 每步无报错,视觉符合 mockup

---

## Testing Strategy

### Unit Tests

| Test | Input | Expected Output | Edge Case? |
|---|---|---|---|
| `test_ingest_ok_sample_creates_row` | 空表 + 1 ok gpu | 1 row, ok_count=1 | No |
| `test_ingest_running_average_converges` | 60 samples 均匀分布 | avg 精度 < 0.01 | No |
| `test_ingest_division_by_zero_memory_total` | memory_total=0 | error_count=1 | Yes |
| `test_hour_bucket_truncation_boundary` | 14:59:59 / 15:00:00 | 分别在 14:00 / 15:00 桶 | Yes |
| `test_parse_mixed_ok_and_error_lines` | 3 行,中间 `[N/A]` | 3 个 gpu dict,index 保留 | Yes (核心) |
| `test_nvidia_parsing_error_does_not_lock_availability` | 能 subprocess 但解析错 | `_nvidia_available` 仍为 True | Yes |
| `test_cleanup_deletes_rows_older_than_7d` | 10 行,5 旧 | 5 行 | No |
| `test_client_delete_cascades_gpu_hourly_usage` | 删 client | 关联 row 全删 | No |
| `test_llm_summary_missing_api_key_skips_gracefully` | env 无 key | 无异常,无 new row | Yes |
| `test_render_markdown_safe_escapes_script_tag` | `<script>...</script>` | 被剥离 | Yes (XSS) |

### Edge Cases Checklist
- [x] Empty input(空客户端、空 GPU 数组、空表)
- [x] 大小边界(0 / 100% VRAM,小时边界)
- [x] Invalid types(`[N/A]` 不可 parse)
- [x] Concurrent access(APScheduler job 与 /report 并发 —— SQLite 单写者,靠 `db.session` 隔离;加测试 `test_concurrent_ingest_and_cleanup`)
- [x] Network failure(anthropic API 挂、重试、落 error row)
- [x] Permission denied(未登录访问 `/gpu-report` → 302)
- [x] 向后兼容(旧客户端无 `status` 字段)
- [x] XSS(`gpu.error` 原文、LLM content)
- [x] 时区边界(日/小时截断)

---

## Validation Commands

### Static Analysis

```bash
python -m py_compile server/server.py server/gpu_report.py client/client.py
```
EXPECT: 零语法错误

### Unit Tests

```bash
cd /home/phaedrus/aimlab/omni-status
pytest tests/test_gpu_hourly_ingest.py tests/test_client_gpu_parsing.py -v
```
EXPECT: 全绿

### Integration Tests

```bash
pytest tests/test_report_endpoint.py tests/test_gpu_report_page.py tests/test_dashboard_gpu_error_render.py -v
```
EXPECT: 全绿

### Full Suite with Coverage

```bash
pytest --cov=server --cov=client --cov-report=term-missing --cov-fail-under=80
```
EXPECT: 全绿,总 coverage ≥ 80%

### Database Validation

```bash
sqlite3 server/monitor.db '.tables'
```
EXPECT: 列表包含 `gpu_hourly_usage` 和 `llm_report`

### Browser Validation

```bash
cd server && python server.py
# 浏览器打开 http://localhost:5000/,admin / admin 登录
# 点击 navbar "GPU 报告" 按钮 → 到达 /gpu-report
```
EXPECT:
- dashboard 正常
- 单卡 error 状态显示红框,整机 online
- `/gpu-report` 顶部 4 个 summary 卡片,下方热力图 168 列,Section ③④ 表格

### Manual Validation

- [ ] 启动无异常,日志只有 INFO
- [ ] 客户端上报 60s → 实时 dashboard 刷新
- [ ] 人工注入单卡 error 样本 → 坏卡独立标红,其它卡正常,整机 online
- [ ] admin 登录后访问 /gpu-report,所有 5 个区域正常渲染
- [ ] 热力图 cell hover 显示 tooltip
- [ ] 临时 `export ANTHROPIC_API_KEY=...` + 手工 REPL 调 `generate_llm_summary()` → db 增加 ok 记录,页面显示摘要
- [ ] 删掉 `ANTHROPIC_API_KEY` + 调 `generate_llm_summary()` → 日志 WARN,页面显示"尚未配置"
- [ ] 手工塞入 9 天前的 GpuHourlyUsage 行 → 调 `cleanup_hourly()` → 行删除
- [ ] 删除一个 client → 对应 GpuHourlyUsage 行级联删除(`PRAGMA foreign_keys=ON` 生效)

---

## Acceptance Criteria

- [ ] 所有 35 个 task 完成
- [ ] 所有 validation commands 通过
- [ ] 单元 + 集成测试全绿,coverage ≥ 80%
- [ ] 静态检查无错误
- [ ] Dashboard 现有行为(实时刷新、在线状态、30 天 uptime)不变
- [ ] `/gpu-report` 5 个区域(顶部摘要 + AI 摘要 + ①②③④)全部渲染
- [ ] 客户端单卡 error 不再导致整机掉线
- [ ] 周一 09:00 cron 能触发 LLM 摘要生成(可用 `scheduler.reschedule` 强制一次验证)
- [ ] 设计 mockup(bad-gpu-ui、report-layout)和实际页面视觉一致

## Completion Checklist

- [ ] 代码遵循发现的 naming / error / logging / jinja 模式
- [ ] 错误处理中文描述,match 现有 `logger.error(f"...{e}")` 风格
- [ ] 没有 hardcode 阈值(全部走 `app.config['GPU_REPORT']`)
- [ ] 不可变:每次 upsert 用增量 avg,不原地 mutate 外部对象
- [ ] Tests 遵循 AAA;测试命名 `test_<subject>_<behavior>_<condition>`
- [ ] Secret(ANTHROPIC_API_KEY)仅从 env 读,不入库、不写日志
- [ ] 文档更新(README + spec 已提交)
- [ ] 无需额外问题即可实施(self-contained)

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| 循环 import(server.py ↔ gpu_report.py) | Medium | 启动失败 | `login_required` 和 `db` 抽 `server/auth.py` 或延迟 import |
| APScheduler 在 Flask debug reloader 下双起 | High | 重复任务 / 重复 LLM 账单 | 检查 `WERKZEUG_RUN_MAIN == 'true'`,仅在 reloader 子进程起 |
| SQLite 外键不启用 → 级联不生效 | Medium | 孤儿 GpuHourlyUsage 行 | `PRAGMA foreign_keys=ON` 在 connect 事件里开启 |
| Anthropic SDK 签名变 | Low | LLM agent 崩 | 锁版本 `anthropic>=0.40,<0.50`;重试时降级 WARN 不 ERROR |
| `_nvidia_available=False` 被解析错误锁死(旧 bug 的另一面) | Medium | 客户端长期不上报 GPU | Task 1.1 明确只在 subprocess 层失败时锁;解析失败返回 error 样本但 `_nvidia_available` 保持 True |
| 客户端旧版不升级 | High | 仍可能因 `float('[N/A]')` 整机掉线 | 向后兼容(server 侧 ingest 支持无 `status` 字段);运维人员同步升级 |
| `ingest_hourly_sample` 抛异常把 `db.session` 搞坏 | Medium | `/report` 返回 500 | 把 uptime commit 和 ingest commit 分离;except 里 `db.session.rollback()` |
| 时区 DST 切换 | Low | 小时桶偏移 | 用 `tzlocal` + `DateTime`,DST 边界的桶可能少/多一小时,不致崩 |
| 热力图在 GPU 多 + 7 天下 HTML 体积大 | Low | 加载慢 | 168 × 50 = 8400 cells,CSS grid 可接受;如果成问题改为 `<canvas>` |

---

## Notes

### 实施顺序关键性

Phase 顺序不能调:
- Phase 1 产出的 `status` 契约是 Phase 2 / 3 的输入
- Phase 3 的 dashboard fix 必须在 Phase 1 客户端升级后,否则旧模板收到带 `status` 的 gpu 会在某些 jinja 旧版本上报错(实际 5.1.3 支持 `.get()` 语义,但保险起见顺序如此)
- Phase 4 Scheduler 初始化需要 Phase 5 的 config loader
- Phase 6 依赖 Phase 5 的 LLM 渲染 placeholder

### 跳过 Section ⑤ 的兜底

如果 ANTHROPIC_API_KEY 没配置,整个 Phase 6 的 scheduler job 静默跳过,页面退化为"尚未配置"提示。整个报告页其它功能独立可用。

### 本 plan 与 spec 的一一映射

| spec 节 | plan task |
|---|---|
| 2 (Goals) | 整个 plan |
| 3 (架构隔离) | Task 7.1, 5.1 |
| 4 (数据模型) | Task 2.1 |
| 5 (聚合) | Task 2.2, 2.3, 4.2 |
| 6 (客户端 bug) | Phase 1 |
| 7 (dashboard update) | Phase 3 |
| 8 (报告页) | Phase 5 |
| 9 (LLM) | Phase 6 |
| 10 (配置) | Task 5.1 |
| 11 (错误处理) | Risks 和分散在各 Task 的 GOTCHA |
| 12 (测试) | 各 Phase 的测试 Task + Testing Strategy |
| 13 (依赖) | Task 0.1, 4.1, 6.1 |
| 14 (实施顺序) | Phase 划分 |
| 15 (风险) | Risks |
| 16 (附录契约) | Task 1.1, 5.6 |

### Confidence

- **Confidence score: 8/10** —— 单遍实施可能性高。主要风险是循环 import 和 APScheduler-in-debug 这两件事可能需要一两次 iteration 调出来;测试基础设施从零搭建也有少量摸索成本。全部其它任务都有明确 mirror 模式和完整代码示例。
