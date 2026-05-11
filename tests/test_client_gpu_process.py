"""Phase 2: client 端用户级 GPU 采集单元测试。

不依赖真实 NVIDIA 卡 — 全部通过 monkeypatch subprocess.run + /proc 文件 mock。
"""
import pytest
from unittest.mock import patch, mock_open, MagicMock


# ─── _parse_compute_apps_output ──────────────────────────────────────────────

def test_parse_compute_apps_normal():
    from client import _parse_compute_apps_output
    sample = """
1234, 4096, GPU-aaaa
5678, 2048, GPU-bbbb
"""
    rows = _parse_compute_apps_output(sample)
    assert rows == [(1234, 4096.0, 'GPU-aaaa'), (5678, 2048.0, 'GPU-bbbb')]


def test_parse_compute_apps_skips_blank_and_malformed():
    from client import _parse_compute_apps_output
    sample = """
1234, 4096, GPU-aaaa

not, a, valid, row, here
9999, notanumber, GPU-bad
5678, 2048, GPU-bbbb
"""
    rows = _parse_compute_apps_output(sample)
    assert rows == [(1234, 4096.0, 'GPU-aaaa'),
                    # "not, a, valid, row, here" len(parts)==5: parts[0]="not" → ValueError
                    (5678, 2048.0, 'GPU-bbbb')]


def test_parse_compute_apps_empty():
    from client import _parse_compute_apps_output
    assert _parse_compute_apps_output('') == []


# ─── _parse_pmon_output ──────────────────────────────────────────────────────

def test_parse_pmon_normal():
    from client import _parse_pmon_output
    sample = """# gpu        pid  type    sm   mem   enc   dec   command
# Idx          #   C/G     %     %     %     %   name
    0      1234     C    45    20     0     0   python
    1      5678     C     5     2     0     0   python
"""
    result = _parse_pmon_output(sample)
    assert result == {1234: 45.0, 5678: 5.0}


def test_parse_pmon_handles_dash_for_no_data():
    """MIG 模式下某些列是 - ;sm 是 - 当作 0 处理。"""
    from client import _parse_pmon_output
    sample = """# gpu        pid  type    sm   mem
    0      1234     C     -     -
"""
    result = _parse_pmon_output(sample)
    assert result == {1234: 0.0}


def test_parse_pmon_empty():
    from client import _parse_pmon_output
    assert _parse_pmon_output('') == {}


def test_parse_pmon_only_header():
    from client import _parse_pmon_output
    assert _parse_pmon_output('# gpu pid type sm mem\n') == {}


# ─── _pid_to_username ────────────────────────────────────────────────────────

def test_pid_to_username_via_loginuid():
    """优先走 loginuid。"""
    from client import _pid_to_username

    fake_pwd = MagicMock()
    fake_pwd.getpwuid.return_value = MagicMock(pw_name='alice')

    m_loginuid = mock_open(read_data='1001')
    with patch('builtins.open', m_loginuid), \
         patch.dict('sys.modules', {'pwd': fake_pwd}):
        assert _pid_to_username(1234) == 'alice'
    fake_pwd.getpwuid.assert_called_once_with(1001)


def test_pid_to_username_loginuid_unset_falls_back_to_uid():
    """loginuid 是 4294967295 (未设置) → 走 /proc/<pid>/status。"""
    from client import _pid_to_username

    fake_pwd = MagicMock()
    fake_pwd.getpwuid.return_value = MagicMock(pw_name='bob')

    files = {
        '/proc/9999/loginuid': '4294967295',
        '/proc/9999/status': 'Name:\tprocess\nUid:\t1002\t1002\t1002\t1002\n',
    }

    def fake_open(path, *args, **kw):
        if path in files:
            return mock_open(read_data=files[path]).return_value
        raise FileNotFoundError(path)

    with patch('builtins.open', side_effect=fake_open), \
         patch.dict('sys.modules', {'pwd': fake_pwd}):
        assert _pid_to_username(9999) == 'bob'


def test_pid_to_username_system_uid_filtered():
    """uid < 1000 是系统账户 → 返回 None 让调用方丢弃。"""
    from client import _pid_to_username

    files = {
        '/proc/1/loginuid': '4294967295',
        '/proc/1/status': 'Uid:\t0\t0\t0\t0\n',
    }
    fake_pwd = MagicMock()

    def fake_open(path, *args, **kw):
        if path in files:
            return mock_open(read_data=files[path]).return_value
        raise FileNotFoundError(path)

    with patch('builtins.open', side_effect=fake_open), \
         patch.dict('sys.modules', {'pwd': fake_pwd}):
        assert _pid_to_username(1) is None


def test_pid_to_username_dead_process_returns_none():
    """进程已退出 → 文件读不到 → 返回 None。"""
    from client import _pid_to_username

    with patch('builtins.open', side_effect=FileNotFoundError('proc gone')):
        assert _pid_to_username(99999) is None


def test_pid_to_username_invalid_pid():
    from client import _pid_to_username
    assert _pid_to_username('not-an-int') is None
    assert _pid_to_username(None) is None


# ─── get_gpu_process_info (end-to-end with mocks) ────────────────────────────

@pytest.fixture
def reset_nvidia_cache():
    import client as client_module
    client_module._nvidia_available = None
    yield
    client_module._nvidia_available = None


def test_get_gpu_process_info_aggregates_per_user_per_gpu(reset_nvidia_cache):
    """两个用户在不同卡上各跑一个进程,期望聚合成两行。"""
    from client import get_gpu_process_info

    def fake_run(cmd, **kw):
        out = MagicMock()
        out.returncode = 0
        if 'query-compute-apps' in ' '.join(cmd):
            out.stdout = '1234, 4096, GPU-aaaa\n5678, 8192, GPU-bbbb\n'
        elif 'pmon' in cmd:
            out.stdout = ('# gpu pid type sm mem\n'
                          '0 1234 C 40 20\n'
                          '1 5678 C 70 60\n')
        elif 'query-gpu' in ' '.join(cmd):
            out.stdout = '0, GPU-aaaa\n1, GPU-bbbb\n'
        else:
            out.stdout = ''
        return out

    def fake_pid_to_username(pid):
        return {1234: 'alice', 5678: 'bob'}.get(pid)

    with patch('client.subprocess.run', side_effect=fake_run), \
         patch('client._pid_to_username', side_effect=fake_pid_to_username):
        result = get_gpu_process_info()

    by_user = {(r['user'], r['gpu_index']): r for r in result}
    assert (by_user[('alice', 0)]['mem_mb'], by_user[('alice', 0)]['util_pct']) == (4096.0, 40.0)
    assert (by_user[('bob', 1)]['mem_mb'],   by_user[('bob', 1)]['util_pct'])   == (8192.0, 70.0)


def test_get_gpu_process_info_sums_same_user_multiple_procs(reset_nvidia_cache):
    """同一用户在同一卡上跑两个进程 → 显存求和,利用率取 max。"""
    from client import get_gpu_process_info

    def fake_run(cmd, **kw):
        out = MagicMock()
        out.returncode = 0
        if 'query-compute-apps' in ' '.join(cmd):
            out.stdout = '111, 2000, GPU-x\n222, 3000, GPU-x\n'
        elif 'pmon' in cmd:
            out.stdout = ('# gpu pid type sm mem\n'
                          '0 111 C 30 20\n'
                          '0 222 C 60 40\n')
        elif 'query-gpu' in ' '.join(cmd):
            out.stdout = '0, GPU-x\n'
        else:
            out.stdout = ''
        return out

    with patch('client.subprocess.run', side_effect=fake_run), \
         patch('client._pid_to_username', return_value='alice'):
        result = get_gpu_process_info()

    assert len(result) == 1
    r = result[0]
    assert r['user'] == 'alice'
    assert r['gpu_index'] == 0
    assert r['mem_mb'] == 5000.0
    assert r['util_pct'] == 60.0


def test_get_gpu_process_info_system_user_filtered(reset_nvidia_cache):
    """root 跑的进程被过滤掉,只剩用户进程。"""
    from client import get_gpu_process_info

    def fake_run(cmd, **kw):
        out = MagicMock()
        if 'query-compute-apps' in ' '.join(cmd):
            out.stdout = '111, 100, GPU-x\n222, 4096, GPU-x\n'
        elif 'pmon' in cmd:
            out.stdout = '# h\n0 111 C 1 1\n0 222 C 50 30\n'
        elif 'query-gpu' in ' '.join(cmd):
            out.stdout = '0, GPU-x\n'
        else:
            out.stdout = ''
        return out

    def fake_user(pid):
        return {111: 'root', 222: 'alice'}.get(pid)

    with patch('client.subprocess.run', side_effect=fake_run), \
         patch('client._pid_to_username', side_effect=fake_user):
        result = get_gpu_process_info()

    assert len(result) == 1
    assert result[0]['user'] == 'alice'


def test_get_gpu_process_info_unknown_user_kept_as_unknown(reset_nvidia_cache):
    """进程已退出 / 拿不到 user → 归类到 __unknown__,不丢数据。"""
    from client import get_gpu_process_info

    def fake_run(cmd, **kw):
        out = MagicMock()
        if 'query-compute-apps' in ' '.join(cmd):
            out.stdout = '999, 1024, GPU-x\n'
        elif 'pmon' in cmd:
            out.stdout = '# h\n0 999 C 10 5\n'
        elif 'query-gpu' in ' '.join(cmd):
            out.stdout = '0, GPU-x\n'
        else:
            out.stdout = ''
        return out

    with patch('client.subprocess.run', side_effect=fake_run), \
         patch('client._pid_to_username', return_value=None):
        result = get_gpu_process_info()

    assert len(result) == 1
    assert result[0]['user'] == '__unknown__'


def test_get_gpu_process_info_nvidia_missing(reset_nvidia_cache):
    from client import get_gpu_process_info

    with patch('client.subprocess.run', side_effect=FileNotFoundError):
        assert get_gpu_process_info() == []


def test_get_gpu_process_info_no_processes(reset_nvidia_cache):
    """nvidia-smi 正常但当前没人在用 → []"""
    from client import get_gpu_process_info

    def fake_run(cmd, **kw):
        out = MagicMock()
        out.stdout = ''
        return out

    with patch('client.subprocess.run', side_effect=fake_run):
        assert get_gpu_process_info() == []


def test_get_gpu_process_info_pmon_fails_vram_still_works(reset_nvidia_cache):
    """pmon 在 MIG 上可能失败,显存数据仍然能上报,util=0。"""
    from client import get_gpu_process_info
    from subprocess import SubprocessError

    def fake_run(cmd, **kw):
        if 'pmon' in cmd:
            raise SubprocessError("pmon not supported in MIG mode")
        out = MagicMock()
        if 'query-compute-apps' in ' '.join(cmd):
            out.stdout = '111, 4096, GPU-x\n'
        elif 'query-gpu' in ' '.join(cmd):
            out.stdout = '0, GPU-x\n'
        else:
            out.stdout = ''
        return out

    with patch('client.subprocess.run', side_effect=fake_run), \
         patch('client._pid_to_username', return_value='alice'):
        result = get_gpu_process_info()

    assert len(result) == 1
    assert result[0]['mem_mb'] == 4096.0
    assert result[0]['util_pct'] == 0.0
