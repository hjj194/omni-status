"""client.py 本机 IP 获取逻辑。

回归背景:主机名为纯数字(5090_3 被 systemd 去掉下划线后变成 50903)时,
gethostbyname 把主机名当成 IP 字面量,面板显示 0.0.198.215 而非真实地址。
"""
import socket
from unittest.mock import patch

import pytest


@pytest.mark.parametrize('ip, expected', [
    ('172.28.114.80', True),
    ('10.0.0.10', True),
    ('0.0.198.215', False),
    ('0.0.0.0', False),
    ('127.0.0.1', False),
    ('127.0.1.1', False),
    ('not-an-ip', False),
    ('', False),
])
def test_is_usable_ipv4(ip, expected):
    import client as c
    assert c._is_usable_ipv4(ip) is expected


def test_numeric_hostname_uses_route_source_ip_not_hostname_literal():
    """复现现场:主机名 50903,解析结果是假地址,但路由源地址是真实网卡地址。"""
    import client as c
    with patch.object(c, '_source_ip_towards', return_value='172.28.114.80'), \
         patch('socket.gethostname', return_value='50903'), \
         patch('socket.gethostbyname', return_value='0.0.198.215'):
        assert c.get_ip_address('http://172.28.114.1:5000/report') == '172.28.114.80'


def test_numeric_hostname_literal_rejected_when_no_route():
    """路由也取不到时,宁可报 127.0.0.1 也不能上报 0.0.198.215。"""
    import client as c
    with patch.object(c, '_source_ip_towards', side_effect=OSError('unreachable')), \
         patch('socket.gethostname', return_value='50903'), \
         patch('socket.gethostbyname', return_value='0.0.198.215'):
        assert c.get_ip_address('http://172.28.114.1:5000/report') == '127.0.0.1'


def test_prefers_server_host_as_route_target():
    import client as c
    with patch.object(c, '_source_ip_towards', return_value='192.168.5.20') as src:
        assert c.get_ip_address('http://10.1.2.3:5000/report') == '192.168.5.20'
    src.assert_called_once_with('10.1.2.3')


def test_falls_back_to_public_target_when_server_host_fails():
    import client as c
    calls = []

    def fake(host):
        calls.append(host)
        if host == 'monitor.lab':
            raise socket.gaierror('name resolution failed')
        return '172.28.114.80'

    with patch.object(c, '_source_ip_towards', side_effect=fake):
        assert c.get_ip_address('http://monitor.lab:5000/report') == '172.28.114.80'
    assert calls == ['monitor.lab', '8.8.8.8']


def test_skips_loopback_source_when_server_is_local():
    """服务端和客户端在同一台机器时,去往服务端的源地址是 127.0.0.1,应继续找真实地址。"""
    import client as c
    with patch.object(c, '_source_ip_towards',
                      side_effect=lambda h: '127.0.0.1' if h == '127.0.0.1' else '10.0.0.8'):
        assert c.get_ip_address('http://127.0.0.1:5000/report') == '10.0.0.8'


def test_without_server_url_uses_public_target():
    import client as c
    with patch.object(c, '_source_ip_towards', return_value='10.0.0.8') as src:
        assert c.get_ip_address() == '10.0.0.8'
    src.assert_called_once_with('8.8.8.8')


def test_malformed_server_url_does_not_crash():
    import client as c
    with patch.object(c, '_source_ip_towards', return_value='10.0.0.8') as src:
        assert c.get_ip_address('http://[::1/report') == '10.0.0.8'
    src.assert_called_once_with('8.8.8.8')


def test_hostname_resolution_used_when_routes_fail_and_result_valid():
    import client as c
    with patch.object(c, '_source_ip_towards', side_effect=OSError('no route')), \
         patch('socket.gethostname', return_value='gpu01'), \
         patch('socket.gethostbyname', return_value='172.28.114.81'):
        assert c.get_ip_address('http://172.28.114.1:5000/report') == '172.28.114.81'


def test_everything_fails_returns_loopback_default_and_warns(caplog):
    import client as c
    with patch.object(c, '_source_ip_towards', side_effect=OSError('no route')), \
         patch('socket.gethostbyname', side_effect=socket.gaierror('fail')), \
         caplog.at_level('WARNING'):
        assert c.get_ip_address('http://172.28.114.1:5000/report') == '127.0.0.1'
    assert '无法获取主机IP地址' in caplog.text


def test_source_ip_towards_real_socket_does_not_send_packets():
    """真实 socket 冒烟:UDP connect 到回环地址应返回回环源地址。"""
    import client as c
    assert c._source_ip_towards('127.0.0.1').startswith('127.')


def test_get_system_info_passes_server_url_to_ip_lookup():
    import client as c
    with patch.object(c, 'get_ip_address', return_value='172.28.114.80') as get_ip:
        info = c.get_system_info('test-uuid', 'http://172.28.114.1:5000/report')
    get_ip.assert_called_once_with('http://172.28.114.1:5000/report')
    assert info['ip_address'] == '172.28.114.80'


def test_main_test_mode_passes_configured_server_url(monkeypatch, tmp_path):
    """主流程要把配置里的服务端地址传给 IP 获取逻辑。"""
    from unittest.mock import MagicMock
    import client as c

    cfg_path = tmp_path / 'client.conf'
    cfg_path.write_text('[server]\nurl = http://172.28.114.1:5000/report\nreport_interval = 60\n')
    monkeypatch.setattr(c, 'CONFIG_FILE', str(cfg_path))
    id_file = tmp_path / '.client_id'
    id_file.write_text('mock-uuid-test')
    monkeypatch.setattr(c, 'CLIENT_ID_FILE', str(id_file))
    monkeypatch.setattr('sys.argv', ['client.py', '--test'])

    with patch.object(c, 'get_ip_address', return_value='172.28.114.80') as get_ip, \
         patch('requests.post', return_value=MagicMock(status_code=200)) as post:
        assert c.main() == 0
    get_ip.assert_called_with('http://172.28.114.1:5000/report')
    assert post.call_args.kwargs['json']['ip_address'] == '172.28.114.80'
