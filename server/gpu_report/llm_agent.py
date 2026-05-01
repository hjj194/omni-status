"""Claude Haiku 周报生成 + Markdown 安全渲染。"""
import json
import logging
import os
import time
from datetime import datetime, timedelta

import bleach
import markdown as _md

from server import db, Client, client_realtime_data

from .config import _get_cfg
from .models import GpuHourlyUsage, LlmReport

logger = logging.getLogger('system_monitor_server')


_SYSTEM_PROMPT = """\
你是实验室 GPU 资源使用情况的分析助手。输入是结构化 JSON,请输出简洁的 markdown 周报(< 400 字)。

必须覆盖:
1. 整体利用率趋势(上升/下降/稳定)
2. 长期空闲 GPU(VRAM 均值 < 20% 且低占用小时数 ≥ 120 的卡)
3. 硬件异常(error 样本 > 0 的卡)
4. 可立即调度的卡数量

禁止:
- 不要点名批评任何使用者
- 不要猜测使用者意图
- 不要使用"占卡""嫌疑""浪费"等负面字眼
- 不要输出 JSON,只输出 markdown 正文
"""

_ALLOWED_TAGS = [
    'p', 'h1', 'h2', 'h3', 'h4', 'ul', 'ol', 'li',
    'strong', 'em', 'code', 'pre', 'blockquote', 'br', 'hr',
]


def _weighted_avg(rows, attr):
    total_ok = sum(r.ok_sample_count or 0 for r in rows)
    if total_ok == 0:
        return 0.0
    return sum(getattr(r, attr) * (r.ok_sample_count or 0) for r in rows) / total_ok


def build_llm_payload(now: datetime, cfg: dict) -> dict:
    period_end   = now.replace(hour=0, minute=0, second=0, microsecond=0)
    period_start = period_end - timedelta(days=7)
    low_vram_threshold = cfg.get('longterm_vram_threshold', 20)

    all_rows = (GpuHourlyUsage.query
                .filter(GpuHourlyUsage.hour >= period_start)
                .filter(GpuHourlyUsage.hour < period_end)
                .all())
    grouped: dict = {}
    for r in all_rows:
        grouped.setdefault((r.client_id, r.gpu_index), []).append(r)

    clients_data = []
    for client in Client.query.order_by(Client.display_order).all():
        gpu_stats = []
        for (cid, gidx), row_list in grouped.items():
            if cid != client.id:
                continue
            gpu_stats.append({
                'idx': gidx,
                'name': row_list[-1].gpu_name,
                'vram_avg_7d': round(_weighted_avg(row_list, 'vram_pct_avg'), 1),
                'util_avg_7d': round(_weighted_avg(row_list, 'util_pct_avg'), 1),
                'hours_observed': len(row_list),
                'hours_low_vram': sum(1 for r in row_list
                                      if (r.ok_sample_count or 0) > 0
                                      and r.vram_pct_avg < low_vram_threshold),
                'errors': sum(r.error_count or 0 for r in row_list),
            })
        if gpu_stats:
            clients_data.append({'host': client.hostname, 'gpus': gpu_stats})

    rt = client_realtime_data
    now_t = datetime.now()
    online_clients = sum(
        1 for c in Client.query.all()
        if c.last_seen and (now_t - c.last_seen).total_seconds() < 600
    )
    idle_threshold = cfg.get('idle_vram_threshold', 15)
    idle_count = sum(
        1
        for c in Client.query.all()
        for g in rt.get(c.id, {}).get('gpu', [])
        if g.get('status', 'ok') != 'error'
        and g.get('memory_total', 0) > 0
        and g['memory_used'] / g['memory_total'] * 100 < idle_threshold
    )

    return {
        'period': f"{period_start.date()} ~ {period_end.date()}",
        'clients': clients_data,
        'summary_stats': {
            'total_clients': Client.query.count(),
            'online_clients': online_clients,
            'currently_free': idle_count,
        },
    }


def build_llm_payload_with_period(now: datetime, cfg: dict):
    """Same as build_llm_payload but also returns the period datetimes for DB row."""
    period_end = now.replace(hour=0, minute=0, second=0, microsecond=0)
    period_start = period_end - timedelta(days=7)
    payload = build_llm_payload(now, cfg)
    return payload, period_start, period_end


def _resolve_api_key(cfg: dict) -> str:
    """API key 优先级: 环境变量 > admin 面板设置的值。"""
    env_key = os.environ.get('ANTHROPIC_API_KEY', '').strip()
    cfg_key = cfg.get('llm_api_key', '').strip()
    return env_key or cfg_key


def _build_llm_client(cfg: dict):
    """根据 provider 构建 SDK 客户端,支持 anthropic 和 OpenAI 兼容端点。"""
    api_key = _resolve_api_key(cfg)
    if not api_key:
        return None, "API Key 未配置(设置环境变量 ANTHROPIC_API_KEY 或在管理面板填写)"

    provider = cfg.get('llm_provider', 'anthropic')
    base_url = cfg.get('llm_base_url', '').strip() or None

    try:
        if provider == 'anthropic':
            import anthropic
            kwargs = {'api_key': api_key}
            if base_url:
                kwargs['base_url'] = base_url
            return anthropic.Anthropic(**kwargs), None
        else:
            # OpenAI 兼容端点
            from openai import OpenAI
            kwargs = {'api_key': api_key}
            if base_url:
                kwargs['base_url'] = base_url
            return OpenAI(**kwargs), None
    except ImportError as e:
        return None, f"缺少 SDK: {e}  (pip install anthropic 或 pip install openai)"


def _call_llm(sdk_client, cfg: dict, messages: list, max_tokens: int = 800):
    """统一调用接口,屏蔽 anthropic / openai SDK 差异。

    返回 (content_str, input_tokens, output_tokens) 或抛出异常。
    """
    model = cfg.get('llm_model', 'claude-haiku-4-5-20251001')
    provider = cfg.get('llm_provider', 'anthropic')

    if provider == 'anthropic':
        resp = sdk_client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=[{
                "type": "text",
                "text": _SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }],
            messages=messages,
        )
        content = "".join(b.text for b in resp.content if b.type == 'text')
        return content, resp.usage.input_tokens, resp.usage.output_tokens
    else:
        # OpenAI 兼容:system message 放在 messages 头部
        full_msgs = [{"role": "system", "content": _SYSTEM_PROMPT}] + messages
        resp = sdk_client.chat.completions.create(
            model=model,
            max_tokens=max_tokens,
            messages=full_msgs,
        )
        content = resp.choices[0].message.content or ''
        usage = getattr(resp, 'usage', None)
        in_tok = getattr(usage, 'prompt_tokens', 0) if usage else 0
        out_tok = getattr(usage, 'completion_tokens', 0) if usage else 0
        return content, in_tok, out_tok


def generate_llm_summary():
    cfg = _get_cfg()
    sdk_client, err = _build_llm_client(cfg)
    if sdk_client is None:
        logger.warning(f"跳过 LLM 周报生成: {err}")
        return

    payload, period_start_dt, period_end_dt = build_llm_payload_with_period(
        datetime.now(), cfg)
    payload_json = json.dumps(payload, ensure_ascii=False, indent=2)
    last_err = None

    for attempt in range(3):
        try:
            content, in_tok, out_tok = _call_llm(
                sdk_client, cfg,
                [{"role": "user",
                  "content": f"请分析以下过去一周的 GPU 使用数据,生成中文周报。\n\n数据:\n{payload_json}"}],
            )
            db.session.add(LlmReport(
                generated_at=datetime.now(),
                period_start=period_start_dt,
                period_end=period_end_dt,
                model=cfg.get('llm_model'),
                status='ok',
                content=content,
                input_tokens=in_tok,
                output_tokens=out_tok,
            ))
            db.session.commit()
            logger.info(f"LLM 周报生成成功 {in_tok}in/{out_tok}out")
            return
        except Exception as e:
            last_err = e
            logger.warning(f"LLM 调用第 {attempt + 1} 次失败: {e}")
            if attempt < 2:
                time.sleep([60, 300][attempt])

    db.session.add(LlmReport(
        generated_at=datetime.now(),
        period_start=period_start_dt,
        period_end=period_end_dt,
        model=cfg.get('llm_model'),
        status='error',
        content=f"{type(last_err).__name__}: {last_err}",
    ))
    db.session.commit()
    logger.error(f"LLM 周报生成全部重试失败: {last_err}")


def render_markdown_safe(text: str) -> str:
    """渲染 LLM 输出的 markdown 为 HTML,bleach 清洗后返回。"""
    if not text:
        return ''
    html = _md.markdown(text, extensions=['extra'])
    return bleach.clean(html, tags=_ALLOWED_TAGS, strip=True)
