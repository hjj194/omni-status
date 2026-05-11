"""保留策略 / 阈值 / 时区 等运行时配置的加载与持久化。

三层优先级(由低到高):
1. ``DEFAULT_CFG`` 代码里的硬编码默认值
2. ``server.conf`` ``[gpu_report]`` 段(运维写)
3. ``runtime_settings.json``(管理员面板写)
"""
import json
import logging
import os

from flask import current_app

logger = logging.getLogger('system_monitor_server')

RUNTIME_SETTINGS_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    '..',  # gpu_report_pkg/ 上一层就是 server/
    'runtime_settings.json',
)
RUNTIME_SETTINGS_FILE = os.path.abspath(RUNTIME_SETTINGS_FILE)

DEFAULT_CFG = {
    'retention_days': 7,                 # GpuHourlyUsage 保留天数
    'idle_vram_threshold': 15,
    'heatmap_low_threshold': 20,
    'heatmap_high_threshold': 70,
    'longterm_vram_threshold': 20,
    'longterm_hours_required': 120,
    # LLM 配置
    'llm_provider': 'anthropic',         # 'anthropic' | 'openai'
    'llm_base_url': '',                  # 留空则用 provider 默认;自建端点时填 http://host:port/v1
    'llm_model': 'claude-haiku-4-5-20251001',
    'llm_api_key': '',                   # 留空则从环境变量读取;非空时存明文(管理员知情)
    'llm_schedule_cron': '0 9 * * 1',
    'llm_report_retention': 12,
    'uptime_record_retention_days': 90,
    'timezone': '',
    'user_idle_util_threshold': 10,      # 用户报表中「空跑」util_pct 阈值
}

# Bounds for admin-configurable settings(防御性约束,导入新配置时也用)
SETTING_BOUNDS = {
    'retention_days':              (1, 365),
    'llm_report_retention':        (1, 100),
    'uptime_record_retention_days': (30, 730),
    'user_idle_util_threshold':    (0, 100),
}

# 已知 Anthropic 模型列表(Anthropic 没有 /v1/models 端点)
ANTHROPIC_KNOWN_MODELS = [
    'claude-opus-4-7',
    'claude-sonnet-4-6',
    'claude-haiku-4-5-20251001',
    'claude-3-5-sonnet-20241022',
    'claude-3-5-haiku-20241022',
    'claude-3-haiku-20240307',
]


def load_runtime_settings() -> dict:
    if not os.path.exists(RUNTIME_SETTINGS_FILE):
        return {}
    try:
        with open(RUNTIME_SETTINGS_FILE) as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"读取 runtime_settings.json 失败: {e}")
        return {}


def save_runtime_settings(updates: dict, app=None):
    current = load_runtime_settings()
    current.update(updates)
    tmp = RUNTIME_SETTINGS_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(current, f, indent=2, ensure_ascii=False)
    os.replace(tmp, RUNTIME_SETTINGS_FILE)
    if app is not None:
        # 立即同步到 app.config 让运行中的代码读到新值
        cfg = app.config.setdefault('GPU_REPORT', dict(DEFAULT_CFG))
        cfg.update(updates)
    logger.info(f"runtime_settings 已更新: {updates}")


def load_gpu_report_config(config_parser=None):
    """聚合三层配置后返回最终 dict,供 server.py 启动时调用。"""
    defaults = dict(DEFAULT_CFG)
    if config_parser is not None and 'gpu_report' in config_parser:
        section = config_parser['gpu_report']
        for k, v in defaults.items():
            if k in section and section[k]:
                try:
                    defaults[k] = type(v)(section[k])
                except (ValueError, TypeError):
                    pass
    overrides = load_runtime_settings()
    for k, v in overrides.items():
        if k in defaults:
            try:
                defaults[k] = type(DEFAULT_CFG[k])(v)
            except (ValueError, TypeError):
                pass
    return defaults


def _get_cfg():
    """运行时读取 app.config['GPU_REPORT'],缺失时回退到默认值。"""
    return current_app.config.get('GPU_REPORT', dict(DEFAULT_CFG))
