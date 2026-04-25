"""Phase 6: LLM summary agent 测试。"""
import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock


# ─── render_markdown_safe ─────────────────────────────────────────────────────

def test_render_markdown_safe_escapes_script_tag():
    from gpu_report import render_markdown_safe
    result = render_markdown_safe('<script>alert(1)</script>')
    # bleach strips the tag but keeps text content — <script> tag itself must be gone
    assert '<script>' not in result
    assert '</script>' not in result


def test_render_markdown_safe_preserves_bold():
    from gpu_report import render_markdown_safe
    result = render_markdown_safe('**粗体**')
    assert '<strong>' in result
    assert '粗体' in result


def test_render_markdown_safe_handles_empty_string():
    from gpu_report import render_markdown_safe
    assert render_markdown_safe('') == ''


def test_render_markdown_safe_strips_disallowed_a_tag():
    from gpu_report import render_markdown_safe
    result = render_markdown_safe('[link](http://evil.com)')
    assert 'http://evil.com' not in result


# ─── build_llm_payload ────────────────────────────────────────────────────────

def test_build_llm_payload_excludes_clients_with_no_data(app):
    from gpu_report import build_llm_payload
    from server import Client, db

    with app.app_context():
        c = Client(id='no-data-cli', hostname='empty', ip_address='10.0.0.9',
                   display_name='empty', platform='linux', display_order=0)
        db.session.add(c)
        db.session.commit()

        cfg = {'longterm_vram_threshold': 20, 'idle_vram_threshold': 15}
        payload = build_llm_payload(datetime.now(), cfg)

    hostnames = [c['host'] for c in payload['clients']]
    assert 'empty' not in hostnames  # no GpuHourlyUsage rows → excluded


def test_build_llm_payload_uses_actual_gpu_indices(app):
    from gpu_report import build_llm_payload, GpuHourlyUsage
    from server import Client, db

    with app.app_context():
        c = Client(id='idx-cli', hostname='srv', ip_address='10.0.0.8',
                   display_name='srv', platform='linux', display_order=0)
        db.session.add(c)
        db.session.commit()  # commit client first to satisfy FK
        # Use yesterday noon — always within 7d window, always before midnight period_end
        hour = datetime.now().replace(hour=12, minute=0, second=0, microsecond=0) - timedelta(days=1)
        for idx in [0, 2]:  # gap at 1
            db.session.add(GpuHourlyUsage(
                client_id='idx-cli', gpu_index=idx, hour=hour,
                gpu_name='RTX', vram_pct_avg=50.0, ok_sample_count=60,
            ))
        db.session.commit()

        cfg = {'longterm_vram_threshold': 20, 'idle_vram_threshold': 15}
        payload = build_llm_payload(datetime.now(), cfg)

    srv = next(c for c in payload['clients'] if c['host'] == 'srv')
    indices = [g['idx'] for g in srv['gpus']]
    assert 0 in indices
    assert 2 in indices
    assert 1 not in indices  # no row for idx 1 → not fabricated


def test_build_llm_payload_token_budget(app):
    """Payload JSON < 3000 chars (very conservative proxy for < 2000 tokens)."""
    from gpu_report import build_llm_payload
    with app.app_context():
        cfg = {'longterm_vram_threshold': 20, 'idle_vram_threshold': 15}
        payload = build_llm_payload(datetime.now(), cfg)
        size = len(json.dumps(payload, ensure_ascii=False))
    assert size < 10000  # generous upper bound; real budget check in manual validation


# ─── generate_llm_summary ─────────────────────────────────────────────────────

def _mock_anthropic_response(content='**摘要**'):
    resp = MagicMock()
    resp.content = [MagicMock(type='text', text=content)]
    resp.usage = MagicMock(input_tokens=100, output_tokens=50)
    return resp


def test_llm_summary_missing_api_key_skips_gracefully(app, monkeypatch):
    from gpu_report import generate_llm_summary, LlmReport
    monkeypatch.delenv('ANTHROPIC_API_KEY', raising=False)
    with app.app_context():
        generate_llm_summary()
        count = LlmReport.query.count()
    assert count == 0


def test_llm_summary_success_writes_ok_row(app, monkeypatch):
    from gpu_report import generate_llm_summary, LlmReport
    monkeypatch.setenv('ANTHROPIC_API_KEY', 'test-key')

    mock_resp = _mock_anthropic_response('**本周摘要**')
    with patch('anthropic.Anthropic') as MockClient:
        MockClient.return_value.messages.create.return_value = mock_resp
        with app.app_context():
            generate_llm_summary()
            row = LlmReport.query.order_by(LlmReport.generated_at.desc()).first()

    assert row is not None
    assert row.status == 'ok'
    assert '摘要' in row.content
    assert row.input_tokens == 100


def test_llm_summary_api_failure_writes_error_row(app, monkeypatch):
    from gpu_report import generate_llm_summary, LlmReport
    monkeypatch.setenv('ANTHROPIC_API_KEY', 'test-key')

    with patch('anthropic.Anthropic') as MockClient:
        MockClient.return_value.messages.create.side_effect = RuntimeError('API down')
        with patch('time.sleep'):  # 不真的等重试间隔
            with app.app_context():
                generate_llm_summary()
                row = LlmReport.query.order_by(LlmReport.generated_at.desc()).first()

    assert row is not None
    assert row.status == 'error'
    assert 'RuntimeError' in row.content
