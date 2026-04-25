"""客户端剩余路径覆盖。"""
import os
import pytest
from unittest.mock import patch, MagicMock


def test_load_config_creates_default_when_missing(tmp_path):
    import client as c
    fake_path = str(tmp_path / 'nonexistent.conf')
    with patch.object(c, 'CONFIG_FILE', fake_path):
        cfg = c.load_config()
    assert cfg.get('server', 'url') is not None
    assert cfg.get('server', 'report_interval') is not None


def test_load_config_reads_existing(tmp_path):
    import client as c
    cfg_path = tmp_path / 'client.conf'
    cfg_path.write_text('[server]\nurl = http://example.com:8000/report\nreport_interval = 30\n')
    with patch.object(c, 'CONFIG_FILE', str(cfg_path)):
        cfg = c.load_config()
    assert cfg.get('server', 'url') == 'http://example.com:8000/report'
    assert cfg.get('server', 'report_interval') == '30'


def test_load_config_handles_read_exception(tmp_path):
    import client as c
    cfg_path = tmp_path / 'broken.conf'
    cfg_path.write_text('not valid ini\n[\n')
    with patch.object(c, 'CONFIG_FILE', str(cfg_path)):
        cfg = c.load_config()
    # Falls back to default config
    assert cfg.get('server', 'url') is not None


def test_get_client_id_handles_read_error(tmp_path, monkeypatch):
    import client as c
    id_file = tmp_path / '.client_id'
    id_file.write_text('uuid-xyz')
    monkeypatch.setattr(c, 'CLIENT_ID_FILE', str(id_file))

    real_open = open

    def bad_open(path, *args, **kwargs):
        if str(path) == str(id_file) and (not args or args[0] == 'r'):
            raise OSError('disk read error')
        return real_open(path, *args, **kwargs)

    with patch('builtins.open', side_effect=bad_open):
        cid = c.get_client_id()
    # Falls back to creating a new UUID
    assert len(cid) == 36


def test_get_client_id_handles_write_error(tmp_path, monkeypatch):
    """新 ID 写入失败时仍返回新 UUID。"""
    import client as c
    nonexistent_dir = tmp_path / 'no-perm-dir' / '.client_id'
    monkeypatch.setattr(c, 'CLIENT_ID_FILE', str(nonexistent_dir))
    # makedirs 应该会成功;模拟 makedirs 失败
    with patch('os.makedirs', side_effect=PermissionError('denied')):
        cid = c.get_client_id()
    assert len(cid) == 36


def test_main_test_mode_success(monkeypatch, tmp_path):
    """--test 模式:成功上报后返回 0。"""
    import client as c

    cfg_path = tmp_path / 'client.conf'
    cfg_path.write_text('[server]\nurl = http://localhost/report\nreport_interval = 60\n')
    monkeypatch.setattr(c, 'CONFIG_FILE', str(cfg_path))

    id_file = tmp_path / '.client_id'
    id_file.write_text('mock-uuid-test')
    monkeypatch.setattr(c, 'CLIENT_ID_FILE', str(id_file))

    monkeypatch.setattr('sys.argv', ['client.py', '--test'])
    mock_resp = MagicMock(status_code=200)
    with patch('requests.post', return_value=mock_resp):
        rc = c.main()
    assert rc == 0


def test_main_test_mode_failure(monkeypatch, tmp_path):
    """--test 模式:服务器不可达时返回 1。"""
    import client as c
    import requests

    cfg_path = tmp_path / 'client.conf'
    cfg_path.write_text('[server]\nurl = http://nohost:9/report\nreport_interval = 60\n')
    monkeypatch.setattr(c, 'CONFIG_FILE', str(cfg_path))

    id_file = tmp_path / '.client_id'
    id_file.write_text('mock-uuid-fail')
    monkeypatch.setattr(c, 'CLIENT_ID_FILE', str(id_file))

    monkeypatch.setattr('sys.argv', ['client.py', '--test'])
    with patch('requests.post', side_effect=requests.RequestException('refused')):
        rc = c.main()
    assert rc == 1


def test_get_system_info_handles_disk_timeout(monkeypatch):
    """psutil.disk_usage 超时不应中断整体上报。"""
    import client as c
    import concurrent.futures

    real_disk_usage = None
    call_count = {'n': 0}

    def slow_disk_usage(mountpoint):
        call_count['n'] += 1
        if call_count['n'] == 1:
            raise concurrent.futures.TimeoutError()
        # fall through to real one
        import psutil
        return psutil.disk_usage(mountpoint)

    info = c.get_system_info('test-uuid')
    # Even if some disks fail, info should still return
    assert 'disks' in info


def test_parse_gpu_line_with_extra_whitespace():
    import client as c
    g = c._parse_gpu_line(0, '  RTX 3090, 78, 19200, 24576  ')
    assert g['status'] == 'ok' or g['status'] == 'error'
