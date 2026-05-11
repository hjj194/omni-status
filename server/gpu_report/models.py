"""SQLAlchemy ORM 模型 —— GpuHourlyUsage 与 LlmReport。

只定义模型,不放任何业务逻辑。其它模块通过 ``from .models import ...``
拿到模型类,从而避免循环 import。
"""
from datetime import datetime

from server import db


class GpuHourlyUsage(db.Model):
    """每小时 GPU 指标快照,保留 7 天,与 dashboard 实时数据隔离。"""
    __tablename__ = 'gpu_hourly_usage'

    id              = db.Column(db.Integer, primary_key=True)
    client_id       = db.Column(db.String(36),
                                db.ForeignKey('client.id', ondelete='CASCADE'),
                                nullable=False)
    gpu_index       = db.Column(db.Integer, nullable=False)
    hour            = db.Column(db.DateTime, nullable=False)   # 小时起始,本地时区
    gpu_name        = db.Column(db.String(100))
    vram_pct_avg    = db.Column(db.Float, default=0.0)
    vram_pct_peak   = db.Column(db.Float, default=0.0)
    util_pct_avg    = db.Column(db.Float, default=0.0)
    util_pct_peak   = db.Column(db.Float, default=0.0)
    ok_sample_count = db.Column(db.Integer, default=0)
    error_count     = db.Column(db.Integer, default=0)

    __table_args__ = (
        db.UniqueConstraint('client_id', 'gpu_index', 'hour',
                            name='uq_gpu_hourly'),
        db.Index('ix_gpu_hourly_hour', 'hour'),
    )


class GpuUserHourlyUsage(db.Model):
    """每小时 (client × GPU × 用户) 用量快照。

    用于按用户维度统计 GPU 使用情况(GPU 小时数、空跑小时等)。
    与 GpuHourlyUsage 同步清理(7 天保留期)。

    vram 单位是 MB(不是百分比),因为 client 端按进程聚合时不一定知道卡的总显存,
    传 MB 让 server 自己除以总显存得到百分比更可靠。
    """
    __tablename__ = 'gpu_user_hourly_usage'

    id              = db.Column(db.Integer, primary_key=True)
    client_id       = db.Column(db.String(36),
                                db.ForeignKey('client.id', ondelete='CASCADE'),
                                nullable=False)
    gpu_index       = db.Column(db.Integer, nullable=False)
    user_name       = db.Column(db.String(64), nullable=False)
    hour            = db.Column(db.DateTime, nullable=False)
    vram_mb_avg     = db.Column(db.Float, default=0.0)
    vram_mb_peak    = db.Column(db.Float, default=0.0)
    util_pct_avg    = db.Column(db.Float, default=0.0)
    util_pct_peak   = db.Column(db.Float, default=0.0)
    sample_count    = db.Column(db.Integer, default=0)

    __table_args__ = (
        db.UniqueConstraint('client_id', 'gpu_index', 'user_name', 'hour',
                            name='uq_gpu_user_hourly'),
        db.Index('ix_gpu_user_hourly_hour', 'hour'),
        db.Index('ix_gpu_user_hourly_user', 'user_name'),
    )


class LlmReport(db.Model):
    """LLM 周摘要记录,保留最近 12 条(由 cleanup_llm_reports 清理)。"""
    __tablename__ = 'llm_report'

    id            = db.Column(db.Integer, primary_key=True)
    generated_at  = db.Column(db.DateTime, nullable=False, default=datetime.now)
    period_start  = db.Column(db.DateTime, nullable=False)
    period_end    = db.Column(db.DateTime, nullable=False)
    model         = db.Column(db.String(80))
    status        = db.Column(db.String(20), default='ok')   # ok | error
    content       = db.Column(db.Text)
    input_tokens  = db.Column(db.Integer)
    output_tokens = db.Column(db.Integer)

    __table_args__ = (db.Index('ix_llm_report_generated_at', 'generated_at'),)
