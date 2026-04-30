import functools
from flask import session, redirect, url_for, request, flash


def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login', next=request.url))
        # 首次登录强制改密:除了 settings 和 logout,其它 admin 路径全部跳到设置
        if session.get('must_change_password'):
            allowed = {'settings', 'logout', 'static'}
            if request.endpoint not in allowed:
                flash('使用默认密码登录,请立即修改', 'warning')
                return redirect(url_for('settings'))
        return f(*args, **kwargs)
    return decorated_function
