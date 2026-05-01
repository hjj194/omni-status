"""GPU 使用量报告包 —— 与 dashboard 实时监控路径完全隔离。

为了向后兼容,所有原本通过 ``from gpu_report import X`` 可访问的符号
都从这里 re-export。新代码请直接 import 子模块以获得更清晰的依赖关系。
"""
import logging

logger = logging.getLogger('system_monitor_server')

# Models 必须最先 import,确保 SQLAlchemy 注册到 db.metadata
from .models import GpuHourlyUsage, LlmReport  # noqa: F401, E402

# Config 是其他模块的基础
from .config import (  # noqa: F401, E402
    DEFAULT_CFG,
    SETTING_BOUNDS,
    RUNTIME_SETTINGS_FILE,
    load_runtime_settings,
    save_runtime_settings,
    load_gpu_report_config,
)

# Ingest
from .ingest import ingest_hourly_sample  # noqa: F401, E402

# Scheduler + 后台任务
from .scheduler import (  # noqa: F401, E402
    cleanup_hourly,
    cleanup_llm_reports,
    init_scheduler,
)

# LLM Agent
from .llm_agent import (  # noqa: F401, E402
    build_llm_payload,
    build_llm_payload_with_period,
    generate_llm_summary,
    render_markdown_safe,
)

# 数据查询(报告页用)
from .queries import (  # noqa: F401, E402
    get_summary_stats,
    get_idle_gpus,
    get_heatmap_data,
    get_longterm_idle,
    get_error_gpus,
)

# 单机详情
from .detail import get_machine_detail  # noqa: F401, E402

# 管理员存储统计 + 清理操作
from .storage import (  # noqa: F401, E402
    get_storage_stats,
    preview_cleanup_gpu_hourly,
    cleanup_gpu_hourly_older_than,
    preview_cleanup_llm_reports,
    cleanup_llm_reports_keep,
    preview_cleanup_uptime,
    cleanup_uptime_older_than,
    cleanup_log_backups,
    vacuum_database,
)

# Blueprint(必须最后 import,因为路由会用到上面的所有依赖)
from .views import gpu_report_bp  # noqa: F401, E402
