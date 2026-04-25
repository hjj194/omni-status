"""client.py 系统信息采集与上报路径覆盖。"""
import pytest
from unittest.mock import patch, MagicMock
import psutil


def test_get_system_info_returns_required_keys():
    import client as c
    info = c.get_system_info('test-uuid')
    required = {'client_id', 'timestamp', 'hostname', 'ip_address', 'platform',
                'cpu', 'memory', 'disks', 'gpu', 'uptime_seconds'}
    assert required.issubset(info.keys())
    assert info['client_id'] == 'test-uuid'
    assert isinstance(info['cpu']['usage_percent'], float)
    assert isinstance(info['memory']['percent'], float)


def test_get_system_info_gpu_empty_without_nvidia():
    import client as c
    with patch.object(c, '_nvidia_available', False):
        info = c.get_system_info('test-uuid')
    assert info['gpu'] == []


def test_get_system_info_includes_root_disk():
    import client as c
    info = c.get_system_info('test-uuid')
    mounts = [d['mountpoint'] for d in info['disks']]
    assert '/' in mounts


def test_report_to_server_success():
    import client as c
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch('requests.post', return_value=mock_resp) as mock_post:
        result = c.report_to_server('http://localhost:5000/report', {'key': 'val'})
    assert result is True
    mock_post.assert_called_once()


def test_report_to_server_failure_on_error_status():
    import client as c
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = 'Internal Server Error'
    with patch('requests.post', return_value=mock_resp):
        result = c.report_to_server('http://localhost:5000/report', {})
    assert result is False


def test_report_to_server_handles_connection_error():
    import client as c
    import requests
    with patch('requests.post', side_effect=requests.RequestException('connect error')):
        result = c.report_to_server('http://badhost:9999/report', {})
    assert result is False


def test_get_client_id_reads_existing_file(tmp_path):
    import client as c
    id_file = tmp_path / '.client_id'
    id_file.write_text('my-existing-uuid')
    with patch.object(c, 'CLIENT_ID_FILE', str(id_file)):
        cid = c.get_client_id()
    assert cid == 'my-existing-uuid'


def test_get_client_id_creates_new_id(tmp_path):
    import client as c
    id_file = tmp_path / '.client_id'
    with patch.object(c, 'CLIENT_ID_FILE', str(id_file)):
        cid = c.get_client_id()
    assert len(cid) == 36  # UUID format
    assert id_file.read_text() == cid
