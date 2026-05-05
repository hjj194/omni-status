"""Phase 1: 客户端 GPU 解析测试。"""
import pytest
from unittest.mock import patch, MagicMock
import subprocess


@pytest.fixture(autouse=True)
def reset_cache(reset_nvidia_cache):
    pass


def make_result(stdout):
    m = MagicMock()
    m.stdout = stdout
    m.returncode = 0
    return m


# ─── _parse_gpu_line ──────────────────────────────────────────────────────────

def test_parse_ok_line_returns_status_ok():
    import client as c
    g = c._parse_gpu_line(0, 'RTX 3090, 78, 19200, 24576')
    assert g['status'] == 'ok'
    assert g['index'] == 0
    assert g['name'] == 'RTX 3090'
    assert g['utilization'] == 78.0
    assert g['memory_used'] == 19200.0
    assert g['memory_total'] == 24576.0


def test_parse_errored_line_returns_status_error():
    import client as c
    g = c._parse_gpu_line(1, 'RTX 3090, [N/A], [N/A], [N/A]')
    assert g['status'] == 'error'
    assert g['index'] == 1
    assert 'name' in g
    assert 'error' in g


def test_parse_preserves_index_numbering():
    import client as c
    g = c._parse_gpu_line(2, 'A100, 50, 20000, 40000')
    assert g['index'] == 2


def test_parse_handles_numeric_na_gracefully():
    import client as c
    g = c._parse_gpu_line(0, 'RTX 3090, [Not Supported], 0, 24576')
    assert g['status'] == 'error'


# ─── get_nvidia_gpu_info ──────────────────────────────────────────────────────

def test_parse_ok_all_gpus():
    import client as c
    stdout = 'RTX 3090, 78, 19200, 24576\nRTX 4090, 50, 10000, 24576\n'
    with patch('subprocess.run', return_value=make_result(stdout)):
        gpus = c.get_nvidia_gpu_info()
    assert len(gpus) == 2
    assert all(g['status'] == 'ok' for g in gpus)


def test_parse_mixed_ok_and_error_lines():
    """核心 bug 修复验证:一行坏不拖累其它行。"""
    import client as c
    stdout = 'RTX 3090, 78, 19200, 24576\nRTX 3090, [N/A], [N/A], [N/A]\nRTX 3090, 5, 500, 24576\n'
    with patch('subprocess.run', return_value=make_result(stdout)):
        gpus = c.get_nvidia_gpu_info()
    assert len(gpus) == 3
    assert gpus[0]['status'] == 'ok'
    assert gpus[1]['status'] == 'error'
    assert gpus[2]['status'] == 'ok'
    assert gpus[2]['index'] == 2  # index 不因坏卡缺失而偏移


def test_parse_all_errored_output():
    import client as c
    stdout = 'RTX 3090, [N/A], [N/A], [N/A]\nRTX 3090, [N/A], [N/A], [N/A]\n'
    with patch('subprocess.run', return_value=make_result(stdout)):
        gpus = c.get_nvidia_gpu_info()
    assert len(gpus) == 2
    assert all(g['status'] == 'error' for g in gpus)


def test_nvidia_unavailable_when_binary_missing():
    import client as c
    with patch('subprocess.run', side_effect=FileNotFoundError):
        gpus = c.get_nvidia_gpu_info()
    assert gpus == []
    assert c._nvidia_available is False


def test_nvidia_parsing_error_does_not_lock_availability():
    """解析时的 ValueError 不应把 _nvidia_available 锁成 False。"""
    import client as c
    stdout = 'RTX 3090, [N/A], [N/A], [N/A]\n'
    with patch('subprocess.run', return_value=make_result(stdout)):
        gpus = c.get_nvidia_gpu_info()
    assert c._nvidia_available is True  # subprocess 成功 → 可用性仍为 True
    assert gpus[0]['status'] == 'error'  # 但这张卡是 error


def test_cached_unavailable_returns_empty_without_subprocess():
    import client as c
    c._nvidia_available = False
    with patch('subprocess.run') as mock_run:
        gpus = c.get_nvidia_gpu_info()
    mock_run.assert_not_called()
    assert gpus == []


def test_timeout_sets_unavailable():
    import client as c
    with patch('subprocess.run', side_effect=subprocess.TimeoutExpired('nvidia-smi', 5)):
        gpus = c.get_nvidia_gpu_info()
    assert gpus == []
    # 瞬时超时不永久禁用（None = 下次周期重试），只有 FileNotFoundError 才永久设 False
    assert c._nvidia_available is None
