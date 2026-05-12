"""Pass 2: bootstrap 路径的烟雾测试。

直接调用 _bootstrap() 没意义(测试模式下短路),所以这些测试用 import-time
副作用来验证:模块加载之后 app 应该已经可用 + 没有抛异常。
"""
import os


def test_app_module_imports_without_main_block():
    """gunicorn server:app 会跳过 __main__ 块,但模块加载本身不应出错。"""
    import server  # 已经在 conftest 中 import 过,这里再 import 是 no-op
    assert hasattr(server, 'app')
    assert hasattr(server, 'db')
    assert callable(getattr(server, '_bootstrap', None))


def test_bootstrap_is_skipped_in_test_mode():
    """conftest 设置 FLASK_TESTING_DB,_is_testing 为 True,_bootstrap 应该早返回。"""
    import server
    assert server._is_testing is True


def test_blueprint_registered_at_module_load():
    """gpu_report 蓝图必须在模块加载阶段注册,这样 WSGI 启动也能命中所有路由。"""
    from server import app
    blueprint_names = {bp.name for bp in app.blueprints.values()}
    assert 'gpu_report' in blueprint_names


def test_routes_available_at_module_load(client):
    """烟雾测试: WSGI 启动场景下(模块导入即用),核心路由应该已经挂上。"""
    # /healthz 不需要登录
    resp = client.get('/healthz')
    assert resp.status_code == 200


def test_gpu_report_config_loaded_at_module_load():
    from server import app
    assert 'GPU_REPORT' in app.config
    cfg = app.config['GPU_REPORT']
    # DEFAULT_CFG 的几个关键键存在
    assert 'retention_days' in cfg
    assert 'user_idle_util_threshold' in cfg
