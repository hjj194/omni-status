# GPU 使用汇总报告与低使用提示 —— 设计规范

- **Spec 日期**: 2026-04-24
- **目标受众**: omni-status 项目维护者、导师/管理员
- **状态**: 待实施
- **相关代码**: `server/server.py`, `server/templates/dashboard.html`, `client/client.py`

---

## 1. 背景与动机

omni-status 当前只提供实时 dashboard(每 60s 刷新一次,数据仅存内存),缺少两类能力:

1. **使用量的时间维度汇总**:导师无法知道"这张卡过去一周被用了多久"、"哪些卡长期被闲置"。
2. **GPU 级别故障隔离**:客户端解析 `nvidia-smi` 输出时,一张卡返回 `[N/A]`(XID / 驱动挂起)会导致整次上报抛 `ValueError`,最终表现为"整机掉线",无法定位具体故障卡。

本次工作同时解决两件事,因为它们共享同一批数据流:新的 `GpuHourlyUsage` 表依赖客户端先把"单卡状态"和"上报成功/失败"解耦,否则 7 天窗口里会出现被掩盖的空洞,聚合统计失真。

## 2. 目标 / 非目标

### 2.1 目标

- **G1** 持久化每台客户端、每张 GPU 的小时级 VRAM / util 指标,保留 7 天。
- **G2** 在 admin 登录后的 `/gpu-report` 页面提供:顶部摘要、当前空闲 GPU、7 天热力图、长期空闲 GPU、硬件异常记录、LLM 周摘要。
- **G3** 修复客户端"单卡错误导致整机掉线"的 bug,升级数据契约表达卡级别状态。
- **G4** 实时 dashboard 的任何路径都不得被新功能阻塞或拖累(异常隔离)。
- **G5** 单元 + 集成测试覆盖 ≥ 80%。

### 2.2 非目标

- 不做跨机器的 GPU 调度、任务分配、用户归属追踪。
- 不做单独的告警系统(邮件/IM push / webhook);警示只内嵌在报告页。
- 不做"长期占卡嫌疑"的自动识别(`VRAM 高 + util 低`)—— 尊重使用者的占用意图,避免得罪人。
- 不替换现有 `UptimeRecord`(每日在线/离线快照仍然独立存在)。
- 不把 Prometheus / Grafana / 时序数据库引入项目。

## 3. 架构与隔离边界

### 3.1 代码隔离

新增文件 `server/gpu_report.py`,以 Flask Blueprint 方式注册。`server.py` 仅做:

```python
from gpu_report import gpu_report_bp, ingest_hourly_sample
app.register_blueprint(gpu_report_bp)
```

所有小时聚合、报告渲染、LLM 摘要逻辑都在 `gpu_report.py` 内。

### 3.2 数据表隔离

新表 `gpu_hourly_usage` 与 `llm_report`;与现有 `client` 表只通过 FK 关联(`ON DELETE CASCADE`),与 `uptime_record` / `announcement` 无交互。

### 3.3 写入通路隔离

`/report` 端点原有的实时 dashboard 写入路径(`client_realtime_data` + `_record_uptime`)保持不变。末尾追加一次 `ingest_hourly_sample(...)` 调用,**用 try/except 包裹**,写统计失败不影响 dashboard 可用性:

```python
try:
    for gpu in data.get('gpu', []):
        ingest_hourly_sample(data['client_id'], gpu, datetime.now())
except Exception as e:
    logger.warning(f"GPU 小时样本写入失败: {e}")
```

### 3.4 权限边界

| 端点 | 登录 | 访问者 |
|---|---|---|
| `/` | 不需要 | 任何人 |
| `/report` | 不需要 | 客户端(POST) |
| `/gpu-report` | `@login_required` | 仅 admin |
| `/gpu-report/api/heatmap.json` | `@login_required` | 仅 admin |
| `/gpu-report/api/idle.json` | `@login_required` | 仅 admin |

## 4. 数据模型

### 4.1 `GpuHourlyUsage` 表

```python
class GpuHourlyUsage(db.Model):
    __tablename__ = 'gpu_hourly_usage'

    id             = db.Column(db.Integer, primary_key=True)
    client_id      = db.Column(db.String(36),
                       db.ForeignKey('client.id', ondelete='CASCADE'),
                       nullable=False)
    gpu_index      = db.Column(db.Integer, nullable=False)
    hour           = db.Column(db.DateTime, nullable=False)   # 小时起始,本地时区
    gpu_name       = db.Column(db.String(100))                 # 最新观测型号,仅用于展示
    vram_pct_avg   = db.Column(db.Float, default=0.0)
    vram_pct_peak  = db.Column(db.Float, default=0.0)
    util_pct_avg   = db.Column(db.Float, default=0.0)
    util_pct_peak  = db.Column(db.Float, default=0.0)
    ok_sample_count    = db.Column(db.Integer, default=0)
    error_count        = db.Column(db.Integer, default=0)

    __table_args__ = (
        db.UniqueConstraint('client_id', 'gpu_index', 'hour',
                            name='uq_gpu_hourly'),
        db.Index('ix_gpu_hourly_hour', 'hour'),
    )
```

**设计要点:**
- `hour` 为整点 `DATETIME`,通过 `now.replace(minute=0, second=0, microsecond=0)` 截取。时区跟随现有 `datetime.now()` 约定使用服务器本地时区(与 `UptimeRecord` 一致)。
- `vram_pct_avg` / `util_pct_avg` 存储增量计算后的小时均值,浮点误差累积 ~ 60 个样本可忽略。
- `vram_pct_peak` / `util_pct_peak` 记录小时峰值,便于看"有没有突刺"。
- `ok_sample_count` 与 `error_count` 互不相加 —— errored 样本不参与均值计算,仅单独计数。
- `gpu_name` 每次写入覆盖为最新值,便于处理换卡场景。

### 4.2 `LlmReport` 表

```python
class LlmReport(db.Model):
    __tablename__ = 'llm_report'

    id             = db.Column(db.Integer, primary_key=True)
    generated_at   = db.Column(db.DateTime, nullable=False, default=datetime.now)
    period_start   = db.Column(db.DateTime, nullable=False)
    period_end     = db.Column(db.DateTime, nullable=False)
    model          = db.Column(db.String(80))
    status         = db.Column(db.String(20), default='ok')   # ok | error
    content        = db.Column(db.Text)                       # markdown / 错误详情
    input_tokens   = db.Column(db.Integer)
    output_tokens  = db.Column(db.Integer)

    __table_args__ = (db.Index('ix_llm_report_generated_at', 'generated_at'),)
```

只保留最近 12 条(约 3 个月),清理由 cron 任务处理。

### 4.3 迁移

SQLite 下,`db.create_all()` 在 `init_db()` 里自动创建新表。`server.py` 的 `init_db()` 已经是幂等的,无需手工迁移脚本。

## 5. 聚合逻辑

### 5.1 Ingest 算法

位于 `server/gpu_report.py`:

```python
def ingest_hourly_sample(client_id: str, gpu: dict, now: datetime) -> None:
    """每个 /report 请求,每张 GPU 调用一次。

    - gpu 形如 {index, name, status: 'ok'|'error', ...}
    - 本函数自己处理 commit? NO —— 留给外层 /report handler 统一 commit
    """
    hour = now.replace(minute=0, second=0, microsecond=0)
    row = (GpuHourlyUsage.query
           .filter_by(client_id=client_id, gpu_index=gpu['index'], hour=hour)
           .first())

    if row is None:
        row = GpuHourlyUsage(
            client_id=client_id,
            gpu_index=gpu['index'],
            hour=hour,
        )
        db.session.add(row)

    row.gpu_name = gpu.get('name') or row.gpu_name

    if gpu.get('status') == 'error':
        row.error_count = (row.error_count or 0) + 1
        return

    if gpu.get('memory_total', 0) <= 0:
        # 非法数据,按错误计数
        row.error_count = (row.error_count or 0) + 1
        return

    vram_pct = gpu['memory_used'] / gpu['memory_total'] * 100
    util_pct = float(gpu.get('utilization', 0))
    n = row.ok_sample_count or 0

    row.vram_pct_avg = (row.vram_pct_avg * n + vram_pct) / (n + 1)
    row.util_pct_avg = (row.util_pct_avg * n + util_pct) / (n + 1)
    row.vram_pct_peak = max(row.vram_pct_peak or 0, vram_pct)
    row.util_pct_peak = max(row.util_pct_peak or 0, util_pct)
    row.ok_sample_count = n + 1
```

### 5.2 保留策略

**APScheduler 后台任务**(新依赖)运行两个 cron:

1. **每小时 05 分**:`DELETE FROM gpu_hourly_usage WHERE hour < now - 7 days`
2. **每周日 03:00**:`DELETE FROM llm_report ORDER BY generated_at DESC OFFSET 12`(保留最近 12 条)

APScheduler 在 Flask 应用启动时初始化:

```python
from apscheduler.schedulers.background import BackgroundScheduler

def init_scheduler(app):
    sched = BackgroundScheduler(timezone=str(time.tzname[0]))
    sched.add_job(cleanup_hourly, 'cron', minute=5)
    sched.add_job(cleanup_llm_reports, 'cron', day_of_week='sun', hour=3)
    sched.add_job(generate_llm_summary, 'cron', day_of_week='mon', hour=9)
    sched.start()
```

选择 APScheduler 理由:周一 9 点的 LLM 摘要定时本身就需要调度器,顺便复用做清理,比在 `/report` 里做 probabilistic cleanup 更干净。

## 6. 客户端 bug 修复

### 6.1 根因

`client/client.py:97-108` 的解析循环:

```python
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
```

当某张卡返回 `[N/A]` / `[Not Supported]`,`float('[N/A]')` 抛 `ValueError`,**不在外层 `except (SubprocessError, FileNotFoundError, TimeoutExpired)` 捕获范围**,异常一路传到 `main()` 的 `except Exception`,整个 `system_info` 构建失败,当次 `/report` 被跳过。若持续抛异常,客户端"沉默",`last_seen` 超 10 分钟 → dashboard 显示整机掉线。

### 6.2 修复方案

改写 `get_nvidia_gpu_info()` 为**按行独立容错**,引入 `status` 字段:

```python
def _parse_gpu_line(i: int, line: str) -> dict:
    try:
        name, utilization, mem_used, mem_total = line.split(', ')
        return {
            'index': i,
            'name': name.strip(),
            'status': 'ok',
            'utilization': float(utilization),
            'memory_used': float(mem_used),
            'memory_total': float(mem_total),
        }
    except (ValueError, IndexError) as e:
        logger.warning(f"GPU {i} 解析失败: {line!r} -> {e}")
        return {
            'index': i,
            'name': (line.split(', ')[0].strip()
                     if ',' in line else f'GPU{i}'),
            'status': 'error',
            'error': line.strip(),
            'timestamp': datetime.now().isoformat(),
        }


def get_nvidia_gpu_info() -> list[dict]:
    global _nvidia_available
    if _nvidia_available is False:
        return []
    try:
        result = subprocess.run(
            ['nvidia-smi',
             '--query-gpu=name,utilization.gpu,memory.used,memory.total',
             '--format=csv,noheader,nounits'],
            capture_output=True, text=True, check=True, timeout=5,
        )
        _nvidia_available = True
    except (subprocess.SubprocessError, FileNotFoundError,
            subprocess.TimeoutExpired):
        if _nvidia_available is None:
            logger.debug('未检测到 NVIDIA GPU 或 nvidia-smi 不可用')
        _nvidia_available = False
        return []

    gpus = []
    for i, line in enumerate(result.stdout.strip().split('\n')):
        if line.strip():
            gpus.append(_parse_gpu_line(i, line))
    return gpus
```

### 6.3 ok 样本契约(给 server)

```json
{
  "index": 0,
  "name": "NVIDIA GeForce RTX 3090",
  "status": "ok",
  "utilization": 78,
  "memory_used": 19200,
  "memory_total": 24576
}
```

### 6.4 error 样本契约

```json
{
  "index": 1,
  "name": "NVIDIA GeForce RTX 3090",
  "status": "error",
  "error": "NVIDIA GeForce RTX 3090, [N/A], [N/A], [N/A]",
  "timestamp": "2026-04-24T14:22:11"
}
```

### 6.5 向后兼容

旧客户端上报的 GPU 项没有 `status` 字段。server 侧 `ingest_hourly_sample` 中视 `gpu.get('status')` 为 `None` 时等价于 `'ok'`(走数值路径,若 `memory_total` 有效则正常累积)。这样 mixed fleet(部分机升级,部分没升)不至于崩。

## 7. Dashboard 更新 —— 卡级别状态渲染

### 7.1 模板改动

`server/templates/dashboard.html` 的 GPU 循环(line 269 起):

- 对 `gpu.status == 'error'`:单独一个红色 card,显示 GPU 名称 + "硬件/驱动异常" + 原始错误字符串 + 最近一次正常读数时间(用 `last_ok_at`,见下)。
- 对 `gpu.status == 'ok'`(或未指明,兼容旧客户端):保持现有渲染。
- 整机 `is_online` 判定不变,依然基于 `last_seen < 10min`。只要客户端在正常上报(即使全部 GPU 都是 error),整机保持在线。

### 7.2 `last_ok_at` 计算

server `/report` 处理时,对每张 `status='ok'` 的 GPU 更新 `client_realtime_data[client_id]['gpu_last_ok'][gpu_index] = now`。在渲染 dashboard 时,若当前 GPU `status='error'`,从该 dict 读取并显示"上次正常读数 X 分钟前"。失败时 fallback 到 "未知"。

### 7.3 Jinja2 均值计算修正

现有 `dashboard.html` 第 270 行用 `gpu.utilization` 和 `gpu.memory_used` 计算均值。需要在循环前先过滤掉 `status='error'` 的项,否则 `gpu.utilization` 不存在会 500。

## 8. 报告页 `/gpu-report` 设计

### 8.1 路由

- `GET /gpu-report` —— 渲染 `templates/gpu_report.html`
- `GET /gpu-report/api/heatmap.json?days=7` —— 返回 JSON,给前端图表用
- `GET /gpu-report/api/idle.json` —— 当前空闲 GPU 列表

全部 `@login_required`。

### 8.2 页面结构(自上而下)

**顶部摘要(4 个小卡)**
- 在线客户端 / 总客户端
- GPU 总数
- 当前空闲 GPU 数(VRAM < 15%,实时)
- 本周异常 GPU 数(`error_count > 0` over 7d)

**① 当前空闲 GPU**
- 源数据:`client_realtime_data` 内存中的最新 GPU 数组
- 判定:`status='ok' AND (memory_used / memory_total) < 0.15`
- 排序:按空闲时长降序(需要回查 `GpuHourlyUsage` 找到上次 VRAM ≥ 15% 的小时)
- 展示:网格卡片,每张卡显示 `hostname · GPU idx · 型号 · 当前 VRAM% · 已空闲 Xh`

**② 7 天 VRAM 占用热力图**
- 客户端 × GPU 为行,168 小时为列
- 单元格颜色:
  - 绿 `#86efac`:`vram_pct_avg < 20%`
  - 黄 `#fbbf24`:`20% ≤ vram_pct_avg < 70%`
  - 红 `#ef4444`:`vram_pct_avg ≥ 70%`
  - 灰 `#6b7280`:该小时无数据,或 `error_count > ok_sample_count`
- 悬停 tooltip 显示精确数值(VRAM avg/peak, util avg/peak, 样本数, 错误数)
- 纯 HTML + CSS Grid 实现,不引入 Chart.js(首期)

**③ 长期空闲 GPU**
- 判定:**过去 7 天 `vram_pct_avg < 20%` 且"低占用小时数" ≥ 120 / 168**
  - 其中"低占用小时"定义为该小时 `vram_pct_avg < 20%`
- **不包含** `VRAM 高 + util 低` 的情况(非目标 NG3)
- 表格列:机器 / GPU / 7d VRAM 均值 / 7d util 均值 / 低占用小时数
- 表头上方说明:"以下 GPU 近 7 天 VRAM 长期低占用,可考虑重新分配或复查是否有访问/调度障碍。"

**④ 硬件异常记录**
- 判定:7 天内 `error_count > 0` 的 (client, gpu) 组合
- 表格列:机器 / GPU / 报错小时数 / 报错样本总数 / 最近报错内容(从最近一次 `GpuHourlyUsage` row 或 `client_realtime_data` 的 error 样本中取)

**⑤ LLM 周摘要(见第 9 节)**
- 位置:实际在顶部摘要下方、Section ① 上方(视觉上这是"阅读起点")
- 由 Section 9 的 agent 生成

### 8.3 前端技术选型

- 保持现有 Bootstrap 5 + Bootstrap Icons 的风格(参考 dashboard.html)
- 热力图用 CSS Grid + `<div>` 单元格,无 JS 库
- tooltip 用 Bootstrap 的 `data-bs-toggle="tooltip"`
- 折叠展开(Section ⑤ 历史、单 GPU 详细折线图)用 Bootstrap Collapse

## 9. LLM 自然语言摘要 Agent

### 9.1 触发

APScheduler cron:`day_of_week='mon', hour=9, minute=0`(可通过 `server.conf` 的 `llm_schedule_cron` 覆盖)。

### 9.2 数据准备

```python
def build_llm_payload(now: datetime) -> dict:
    period_end = now.replace(hour=0, minute=0, second=0, microsecond=0)
    period_start = period_end - timedelta(days=7)

    clients_data = []
    for client in Client.query.order_by(Client.display_order).all():
        gpu_stats = []
        for gpu_idx in range(_MAX_GPU_INDEX):
            rows = (GpuHourlyUsage.query
                    .filter_by(client_id=client.id, gpu_index=gpu_idx)
                    .filter(GpuHourlyUsage.hour >= period_start)
                    .all())
            if not rows:
                continue
            gpu_stats.append({
                'idx': gpu_idx,
                'name': rows[-1].gpu_name,
                'vram_avg_7d': round(_weighted_avg(rows, 'vram_pct_avg'), 1),
                'util_avg_7d': round(_weighted_avg(rows, 'util_pct_avg'), 1),
                'hours_observed': len(rows),
                'hours_low_vram': sum(1 for r in rows if r.vram_pct_avg < 20),
                'errors': sum(r.error_count for r in rows),
            })
        if gpu_stats:
            clients_data.append({'host': client.hostname, 'gpus': gpu_stats})

    return {
        'period': f"{period_start.date()} ~ {period_end.date()}",
        'clients': clients_data,
        'summary_stats': _global_summary(period_start, period_end),
    }
```

Payload 目标:< 2000 input tokens(Haiku 定价下约 0.001 元)。

### 9.3 Prompt 设计

**System prompt**(使用 prompt caching):

```
你是实验室 GPU 资源使用情况的分析助手。输入是结构化 JSON,输出简洁的 markdown 周报(< 400 字)。

必须覆盖:
1. 整体利用率趋势(上升/下降/稳定)
2. 长期空闲 GPU(VRAM 均值 < 20% 且低占用小时数 ≥ 120 的卡)
3. 硬件异常(errors > 0 的卡)
4. 可立即调度的卡(从 summary_stats.currently_free)

禁止:
- 不要点名批评任何使用者
- 不要猜测使用者意图
- 不要用"占卡"、"嫌疑"、"浪费"等字眼
- 不要输出 JSON,只输出 markdown 正文
```

**User message**:

```
请分析以下过去一周的 GPU 使用数据,生成中文周报。

数据:
{payload_json}
```

### 9.4 API 调用

- 模型:`claude-haiku-4-5-20251001`(默认,可配置)
- 启用 prompt caching(system prompt 标记 cache_control)
- `max_tokens`: 800
- 超时:30s
- 重试:失败后最多 2 次,间隔 60s、300s

### 9.5 持久化与展示

成功:写入 `LlmReport(status='ok', content=<markdown>, input_tokens, output_tokens)`。

失败(所有重试都失败):写入 `LlmReport(status='error', content=<error message>)`。

报告页渲染:
- 最新一条 `status='ok'` 的 markdown 内容展示在顶部(用 `markdown` python 库或前端 `marked.js` 渲染)
- 右上角一个 "查看历史摘要" 链接,展开显示过去 12 周的摘要
- 如果最新一条是 `status='error'`,显示"上次摘要生成失败(X 时间前),详情见日志",下方回退显示上一条成功的摘要

### 9.6 机密管理

- `ANTHROPIC_API_KEY` 从 env 读取
- 启动时若未设置,scheduler 的 `generate_llm_summary` 任务跳过执行并日志 WARNING
- 页面显示"未配置 API key,LLM 摘要功能未启用",其余报告功能正常工作

## 10. 配置

`server/server.conf` 新增 `[gpu_report]` 段(带默认值):

```ini
[gpu_report]
retention_days = 7
idle_vram_threshold = 15            ; Section ① "当前空闲" 的 VRAM% 上限
heatmap_low_threshold = 20          ; 热力图绿色
heatmap_high_threshold = 70         ; 热力图红色
longterm_vram_threshold = 20        ; Section ③ "长期空闲" VRAM 均值上限
longterm_hours_required = 120       ; Section ③ 至少这么多小时达标
llm_model = claude-haiku-4-5-20251001
llm_schedule_cron = 0 9 * * 1       ; 周一 9:00
llm_report_retention = 12           ; 保留最近 N 条
```

`load_config()` 扩展读取 `[gpu_report]` 段,落到 `app.config['GPU_REPORT']`。

## 11. 错误处理

| 失败场景 | 预期行为 |
|---|---|
| `ingest_hourly_sample` 抛异常 | `/report` handler 吞掉并记 WARN,dashboard 仍然可用 |
| APScheduler cleanup 失败 | 记 ERROR,下次重试,不影响应用启动 |
| LLM API 超时 / 额度不足 | 重试 2 次,失败后写 `LlmReport(status='error')`,页面回退显示上周摘要 |
| `ANTHROPIC_API_KEY` 未设置 | 摘要任务跳过,页面提示"未配置",其他功能正常 |
| 客户端单卡解析失败 | 单张 GPU 显示 `status='error'`,其他 GPU 正常,整机在线 |
| SQLite 临时锁定 | Flask-SQLAlchemy 自动重试;超过则 `/report` 返回 500,客户端下个 60s 周期重试 |
| `GpuHourlyUsage.memory_total == 0` | ingest 视为 error,不污染均值 |

## 12. 测试策略

### 12.1 单元测试 `tests/test_gpu_report.py`

- `test_ingest_ok_sample_creates_row`
- `test_ingest_ok_sample_updates_existing_row`
- `test_ingest_errored_sample_increments_error_count`
- `test_ingest_errored_sample_does_not_touch_averages`
- `test_ingest_running_average_converges_to_true_mean`(60 次样本,断言 `abs(avg - expected) < 0.01`)
- `test_ingest_peak_tracking`
- `test_ingest_division_by_zero_memory_total_treated_as_error`
- `test_hour_bucket_truncation`(14:00:00 / 14:59:59 → 14:00:00;15:00:00 → 15:00:00)
- `test_ingest_missing_status_treated_as_ok`(向后兼容)

### 12.2 保留任务测试

- `test_cleanup_deletes_rows_older_than_7d`
- `test_cleanup_keeps_exactly_7d_boundary`
- `test_cleanup_llm_reports_keeps_latest_12`
- `test_client_delete_cascades_gpu_hourly_usage`

### 12.3 集成测试 `tests/test_report_endpoint.py`

- `test_report_endpoint_ingests_hourly_sample`
- `test_report_endpoint_tolerates_ingest_failure`(monkeypatch ingest → raise)
- `test_gpu_report_page_requires_login`
- `test_gpu_report_page_renders_with_no_data`
- `test_gpu_report_page_renders_with_partial_data`
- `test_heatmap_api_returns_correct_168_hours`
- `test_idle_api_excludes_errored_gpus`

### 12.4 客户端测试 `tests/test_client_gpu_parsing.py`

- `test_parse_ok_line`
- `test_parse_errored_line_returns_status_error`
- `test_parse_mixed_ok_and_error_lines`(核心:1 行坏不拖累其它)
- `test_parse_preserves_index_numbering`(GPU 1 坏 → GPU 2 的 index 还是 2)
- `test_parse_handles_all_errored_output`
- `test_nvidia_unavailable_cached_permanently`
- `test_nvidia_parsing_error_does_not_lock_availability`(解析错误不应把 `_nvidia_available` 锁成 False)

### 12.5 LLM agent 测试 `tests/test_llm_summary.py`

- `test_build_llm_payload_token_budget_under_2000`(序列化后 tokenize 粗估)
- `test_build_llm_payload_excludes_clients_with_no_data`
- `test_weighted_avg_computation`
- `test_llm_summary_success_writes_report_row`(mock anthropic SDK)
- `test_llm_summary_api_failure_writes_error_row_after_retries`
- `test_llm_summary_missing_api_key_skips_gracefully`
- `test_llm_report_html_rendering_escapes_xss`(markdown → html 防 XSS)

### 12.6 UI 冒烟测试(手工)

- 登录 → `/gpu-report` 可访问,未登录重定向
- 热力图 168 小时格子对齐
- 中文字符不乱码
- 至少一台客户端有坏卡时,整机仍在线,坏卡红色

### 12.7 覆盖率

- 目标 ≥ 80%(rules/common/testing.md 要求)
- 执行:`pytest --cov=server --cov=client --cov-report=term-missing --cov-fail-under=80`
- `server/gpu_report.py` 和 `client/client.py` 的 GPU 解析路径要求 ≥ 90%

## 13. 依赖变更

`server/requirements.txt` 新增:

```
APScheduler>=3.10
anthropic>=0.40
markdown>=3.5
bleach>=6.0       # XSS 过滤,markdown 渲染后清洗
```

`client/requirements.txt` 无变化。

## 14. 实施顺序建议

按独立可测试单元:

1. **客户端 bug 修复 + 契约变更**(Section 6)—— 独立,可先上线
2. **数据模型 + ingest 逻辑**(Section 4 + 5.1)—— 不改 UI
3. **dashboard 卡级别错误渲染**(Section 7)—— 消费 Section 6 的新契约
4. **APScheduler 清理任务**(Section 5.2)
5. **`/gpu-report` 页面 ① ② ③ ④**(Section 8)
6. **LLM agent + Section ⑤**(Section 9)—— 最后,依赖上面全部跑通

每一步都能独立部署 + 回滚。

## 15. 风险与未解决问题

### 15.1 时区风险

`datetime.now()` 使用服务器本地时区。若服务器在 UTC,而导师看周报习惯按北京时间,"过去 7 天"的边界可能差 8 小时。

**缓解**:`hour` 全部用服务器本地时间,报告页标题明确标注时区;如需跨时区支持,后续用 UTC 存储 + 前端按浏览器时区展示。

### 15.2 APScheduler 多进程下的重复触发

如果未来用 gunicorn 多 worker 部署,每个 worker 都会起一个 scheduler,可能导致清理任务和 LLM 摘要重复执行。

**缓解**:首期 Flask `app.run()` 单进程部署,无此问题;后续如切到多 worker,用 `apscheduler-sqlalchemy` jobstore + 分布式锁,或把 scheduler 抽成独立进程。

### 15.3 Client 端 nvidia-smi 阻塞

某些硬件故障下 `nvidia-smi` 进入 D 态(uninterruptible),Python `subprocess.run(timeout=5)` 实际无法 kill,整个客户端会卡死。

**缓解**:本 spec 不解决此问题;独立追踪。可以考虑把 nvidia-smi 调用放子进程 + 硬超时 kill(SIGKILL)。

### 15.4 LLM 摘要幻觉

Haiku 可能编造"lab-srv-08 在周三 14:00 利用率暴增"之类不存在的细节。

**缓解**:system prompt 明确"只能基于给定 JSON 的数字事实,不得推断具体时刻";加测试验证摘要中出现的 hostname 都在 input payload 中。

### 15.5 "长期空闲"阈值首期没有实际数据验证

120/168 小时、VRAM < 20% 这两个阈值来自设计猜测,上线后可能误报(或漏报)。

**缓解**:阈值全部走 `server.conf`,导师可以手动调。首期默认值文档化,上线 2 周后 review 一次。

## 16. 附录 —— 数据契约一览

### 16.1 `POST /report` 请求体(客户端 → 服务器)

```json
{
  "client_id": "<uuid>",
  "timestamp": "2026-04-24T15:03:21.123456",
  "hostname": "lab-srv-03",
  "ip_address": "192.168.1.12",
  "platform": "Linux-5.15.0-151-generic-x86_64",
  "cpu": {"count": 64, "usage_percent": 12.3},
  "memory": {"total": 137438953472, "used": 41231234567, "percent": 30.0},
  "disks": [...],
  "gpu": [
    {"index": 0, "name": "RTX 3090", "status": "ok",
     "utilization": 78, "memory_used": 19200, "memory_total": 24576},
    {"index": 1, "name": "RTX 3090", "status": "error",
     "error": "RTX 3090, [N/A], [N/A], [N/A]",
     "timestamp": "2026-04-24T15:03:18.000000"}
  ],
  "uptime_seconds": 1234567
}
```

### 16.2 `GET /gpu-report/api/heatmap.json?days=7` 响应

```json
{
  "period_start": "2026-04-17T00:00:00",
  "period_end":   "2026-04-24T15:00:00",
  "hours": 168,
  "rows": [
    {
      "client_id": "<uuid>",
      "hostname": "lab-srv-03",
      "gpu_index": 1,
      "gpu_name": "RTX 3090",
      "cells": [
        {"hour_offset": 0, "vram_avg": 89.1, "vram_peak": 92.3,
         "util_avg": 3.2, "util_peak": 12.0, "ok": 60, "err": 0},
        {"hour_offset": 1, "vram_avg": null, "err": 60}
      ]
    }
  ]
}
```

### 16.3 `GET /gpu-report/api/idle.json` 响应

```json
{
  "timestamp": "2026-04-24T15:04:00",
  "idle_gpus": [
    {"hostname": "lab-srv-02", "gpu_index": 1, "gpu_name": "RTX 4090",
     "vram_pct": 2.1, "idle_minutes": 131}
  ]
}
```
