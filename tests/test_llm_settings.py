"""LLM 配置面板:save / test / list_models 端点。"""
import json
import pytest
from unittest.mock import patch, MagicMock


# ─── save_llm_settings ──────────────────────────────────────────────────────

def test_save_llm_requires_login(client):
    resp = client.post('/settings/save_llm', data={})
    assert resp.status_code == 302


def test_save_llm_stores_provider_and_model(app, logged_in_client, tmp_path):
    import gpu_report.config as gr_config
    orig = gr_config.RUNTIME_SETTINGS_FILE
    gr_config.RUNTIME_SETTINGS_FILE = str(tmp_path / 'rs.json')
    try:
        resp = logged_in_client.post('/settings/save_llm', data={
            'llm_provider': 'openai',
            'llm_model': 'gpt-4o-mini',
            'llm_base_url': 'http://localhost:11434/v1',
            'llm_schedule_cron': '0 8 * * 1',
        }, follow_redirects=True)
        assert resp.status_code == 200
        with app.app_context():
            cfg = app.config['GPU_REPORT']
            assert cfg['llm_provider'] == 'openai'
            assert cfg['llm_model'] == 'gpt-4o-mini'
            assert cfg['llm_base_url'] == 'http://localhost:11434/v1'
    finally:
        gr_config.RUNTIME_SETTINGS_FILE = orig


def test_save_llm_stores_api_key(app, logged_in_client, tmp_path):
    import gpu_report.config as gr_config
    orig = gr_config.RUNTIME_SETTINGS_FILE
    gr_config.RUNTIME_SETTINGS_FILE = str(tmp_path / 'rs.json')
    try:
        resp = logged_in_client.post('/settings/save_llm', data={
            'llm_api_key': 'sk-test-key-12345',
        }, follow_redirects=True)
        assert resp.status_code == 200
        with open(gr_config.RUNTIME_SETTINGS_FILE) as f:
            data = json.load(f)
        assert data.get('llm_api_key') == 'sk-test-key-12345'
    finally:
        gr_config.RUNTIME_SETTINGS_FILE = orig


def test_save_llm_clears_api_key(app, logged_in_client, tmp_path):
    import gpu_report.config as gr_config
    orig = gr_config.RUNTIME_SETTINGS_FILE
    gr_config.RUNTIME_SETTINGS_FILE = str(tmp_path / 'rs.json')
    # First, set a key
    with open(gr_config.RUNTIME_SETTINGS_FILE, 'w') as f:
        json.dump({'llm_api_key': 'old-key'}, f)
    try:
        resp = logged_in_client.post('/settings/save_llm', data={
            'clear_api_key': '1',
        }, follow_redirects=True)
        assert resp.status_code == 200
        with open(gr_config.RUNTIME_SETTINGS_FILE) as f:
            data = json.load(f)
        assert data.get('llm_api_key') == ''
    finally:
        gr_config.RUNTIME_SETTINGS_FILE = orig


def test_save_llm_ignores_invalid_provider(app, logged_in_client, tmp_path):
    import gpu_report.config as gr_config
    orig = gr_config.RUNTIME_SETTINGS_FILE
    gr_config.RUNTIME_SETTINGS_FILE = str(tmp_path / 'rs.json')
    try:
        resp = logged_in_client.post('/settings/save_llm', data={
            'llm_provider': 'malicious',
        }, follow_redirects=True)
        assert resp.status_code == 200
        with app.app_context():
            assert app.config['GPU_REPORT'].get('llm_provider') != 'malicious'
    finally:
        gr_config.RUNTIME_SETTINGS_FILE = orig


# ─── test_llm_connection ────────────────────────────────────────────────────

def test_test_llm_requires_login(client):
    resp = client.post('/settings/test_llm',
                        data=json.dumps({}), content_type='application/json')
    assert resp.status_code == 302


def test_test_llm_no_api_key_returns_error(app, logged_in_client, monkeypatch):
    monkeypatch.delenv('ANTHROPIC_API_KEY', raising=False)
    with app.app_context():
        app.config['GPU_REPORT']['llm_api_key'] = ''
    resp = logged_in_client.post('/settings/test_llm',
                                  data=json.dumps({'llm_api_key': ''}),
                                  content_type='application/json')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['ok'] is False
    assert 'API Key' in data['error'] or 'api' in data['error'].lower()


def test_test_llm_success(app, logged_in_client, monkeypatch):
    monkeypatch.setenv('ANTHROPIC_API_KEY', 'test-key')

    mock_sdk = MagicMock()
    mock_resp = MagicMock()
    mock_resp.content = [MagicMock(type='text', text='OK')]
    mock_resp.usage = MagicMock(input_tokens=5, output_tokens=2)
    mock_sdk.messages.create.return_value = mock_resp

    with patch('gpu_report.llm_agent._build_llm_client', return_value=(mock_sdk, None)):
        resp = logged_in_client.post('/settings/test_llm',
                                      data=json.dumps({'llm_provider': 'anthropic'}),
                                      content_type='application/json')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['ok'] is True
    assert 'latency_ms' in data
    assert data['response'] == 'OK'


def test_test_llm_api_error(app, logged_in_client, monkeypatch):
    monkeypatch.setenv('ANTHROPIC_API_KEY', 'test-key')

    mock_sdk = MagicMock()
    mock_sdk.messages.create.side_effect = Exception('Connection refused')

    with patch('gpu_report.llm_agent._build_llm_client', return_value=(mock_sdk, None)):
        # Explicitly pass provider to avoid state pollution from other tests
        resp = logged_in_client.post('/settings/test_llm',
                                      data=json.dumps({'llm_provider': 'anthropic',
                                                       'llm_model': 'claude-haiku-4-5-20251001'}),
                                      content_type='application/json')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['ok'] is False


# ─── list_llm_models ────────────────────────────────────────────────────────

def test_list_models_requires_login(client):
    resp = client.get('/settings/llm_models')
    assert resp.status_code == 302


def test_list_models_anthropic_returns_builtin_list(app, logged_in_client):
    with app.app_context():
        app.config['GPU_REPORT']['llm_provider'] = 'anthropic'
    resp = logged_in_client.get('/settings/llm_models')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['ok'] is True
    assert isinstance(data['models'], list)
    assert len(data['models']) > 0
    assert data['source'] == 'built-in list'
    assert 'claude-haiku-4-5-20251001' in data['models']


def test_list_models_openai_calls_api(app, logged_in_client, monkeypatch):
    monkeypatch.setenv('ANTHROPIC_API_KEY', 'test-key')
    with app.app_context():
        app.config['GPU_REPORT']['llm_provider'] = 'openai'
        app.config['GPU_REPORT']['llm_base_url'] = 'http://localhost:11434/v1'

    mock_sdk = MagicMock()
    mock_sdk.models.list.return_value = MagicMock(
        data=[MagicMock(id='llama3'), MagicMock(id='mistral')]
    )

    with patch('gpu_report.llm_agent._build_llm_client', return_value=(mock_sdk, None)):
        resp = logged_in_client.get('/settings/llm_models')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['ok'] is True
    assert 'llama3' in data['models']
    assert data['source'] == 'api'


def test_list_models_openai_api_error(app, logged_in_client, monkeypatch):
    monkeypatch.setenv('ANTHROPIC_API_KEY', 'test-key')
    with app.app_context():
        app.config['GPU_REPORT']['llm_provider'] = 'openai'

    mock_sdk = MagicMock()
    mock_sdk.models.list.side_effect = Exception('Connection refused')

    with patch('gpu_report.llm_agent._build_llm_client', return_value=(mock_sdk, None)):
        resp = logged_in_client.get('/settings/llm_models')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['ok'] is False


# ─── settings page renders LLM config ────────────────────────────────────────

def test_settings_page_shows_llm_config(logged_in_client):
    resp = logged_in_client.get('/settings')
    assert resp.status_code == 200
    html = resp.data.decode()
    assert 'LLM 摘要配置' in html
    assert 'llm_provider' in html
    assert 'llm_model' in html
    assert '测试连接' in html
    assert '检测可用模型' in html


def test_settings_shows_env_badge_when_api_key_in_env(logged_in_client, monkeypatch):
    monkeypatch.setenv('ANTHROPIC_API_KEY', 'sk-ant-test')
    resp = logged_in_client.get('/settings')
    html = resp.data.decode()
    assert '来自 ENV' in html or 'ENV' in html


def test_settings_shows_unconfigured_when_no_key(app, logged_in_client, monkeypatch):
    monkeypatch.delenv('ANTHROPIC_API_KEY', raising=False)
    with app.app_context():
        app.config['GPU_REPORT']['llm_api_key'] = ''
    resp = logged_in_client.get('/settings')
    html = resp.data.decode()
    assert '未配置' in html or 'secondary' in html
