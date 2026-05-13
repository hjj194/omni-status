"""客户端 / 公告管理路由 —— 从 server.py 拆出来,保持 endpoint 名不变。

模块化拆分,**非** Flask Blueprint:
- 路由仍然挂在主 `app` 上(`@app.route(...)`),不带前缀
- endpoint 名保持原样(edit_client / delete_client / ...),所以模板里所有
  url_for() 调用一行不用改
- import 在 server.py 末尾(所有模型/装饰器都已定义之后)避免循环

每个被移过来的函数保持与原版**字节级**等价的逻辑,只换文件位置。
"""
from datetime import datetime

from flask import (
    flash, redirect, render_template, request, session, url_for,
)

from server import (
    Announcement, CONFIG_FILE, Client, app, client_realtime_data, db,
    load_client_configs, logger, save_client_configs,
)
from auth import login_required


@app.route('/reorder', methods=['GET', 'POST'])
@login_required
def reorder_clients():
    """重新排序客户端卡片"""
    if request.method == 'POST':
        client_ids = request.form.getlist('client_ids[]')
        for i, client_id in enumerate(client_ids):
            client = db.session.get(Client, client_id)
            if client:
                client.display_order = i
        db.session.commit()
        save_client_configs()
        flash('客户端显示顺序已更新', 'success')
        return redirect(url_for('dashboard'))

    clients = Client.query.order_by(Client.display_order).all()
    client_data = []
    for client in clients:
        is_online = ((datetime.now() - client.last_seen).total_seconds() < 600
                     if client.last_seen else False)
        client_data.append({
            'id': client.id,
            'hostname': client.hostname,
            'display_name': client.display_name or client.hostname,
            'ip_address': client.ip_address,
            'physical_address': client.physical_address or '未设置',
            'is_online': is_online,
            'display_order': client.display_order,
        })
    return render_template('reorder_clients.html', clients=client_data)


@app.route('/edit_client/<client_id>', methods=['GET', 'POST'])
@login_required
def edit_client(client_id):
    """编辑客户端信息页面 (需要登录)"""
    client = Client.query.get_or_404(client_id)
    if request.method == 'POST':
        client.display_name = request.form.get('display_name')
        client.ip_address = request.form.get('ip_address')
        client.physical_address = request.form.get('physical_address')
        client.notes = request.form.get('notes')
        db.session.commit()
        save_client_configs()
        logger.info(f"Client information updated: {client.hostname} (ID: {client.id})")
        flash('客户端信息已更新', 'success')
        return redirect(url_for('dashboard'))
    return render_template('edit_client.html', client=client)


@app.route('/delete_client/<client_id>', methods=['POST'])
@login_required
def delete_client(client_id):
    """删除客户端记录 (需要登录)"""
    client = Client.query.get_or_404(client_id)
    hostname = client.hostname

    client_realtime_data.pop(client_id, None)
    db.session.delete(client)
    db.session.commit()
    save_client_configs()

    logger.info(f"Client deleted: {hostname} (ID: {client_id})")
    flash(f'客户端 "{hostname}" 已删除', 'success')
    return redirect(url_for('dashboard'))


@app.route('/export_config', methods=['POST'])
@login_required
def export_config():
    """导出客户端配置"""
    if save_client_configs():
        flash(f'客户端配置已导出到 {CONFIG_FILE}', 'success')
    else:
        flash('导出配置失败', 'danger')
    return redirect(url_for('settings'))


@app.route('/import_config', methods=['POST'])
@login_required
def import_config():
    """导入客户端配置"""
    if load_client_configs():
        flash('客户端配置已成功导入', 'success')
    else:
        flash('导入配置失败', 'danger')
    return redirect(url_for('settings'))


# ─── 公告管理 ────────────────────────────────────────────────────────────────

@app.route('/announcements', methods=['GET', 'POST'])
@login_required
def manage_announcements():
    """公告管理页面"""
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'add':
            title = request.form.get('title')
            content = request.form.get('content')
            priority = int(request.form.get('priority', 0))
            if title and content:
                announcement = Announcement(
                    title=title, content=content, priority=priority,
                )
                db.session.add(announcement)
                db.session.commit()
                flash('公告已添加', 'success')
            else:
                flash('标题和内容不能为空', 'danger')

        elif action == 'toggle':
            try:
                announcement_id = int(request.form.get('announcement_id', 0))
            except (ValueError, TypeError):
                announcement_id = 0
            announcement = db.session.get(Announcement, announcement_id)
            if announcement:
                announcement.is_active = not announcement.is_active
                db.session.commit()
                flash(f'公告已{"启用" if announcement.is_active else "禁用"}', 'success')

        elif action == 'delete':
            try:
                announcement_id = int(request.form.get('announcement_id', 0))
            except (ValueError, TypeError):
                announcement_id = 0
            announcement = db.session.get(Announcement, announcement_id)
            if announcement:
                db.session.delete(announcement)
                db.session.commit()
                flash('公告已删除', 'success')

        return redirect(url_for('manage_announcements'))

    announcements = (Announcement.query
                     .order_by(Announcement.priority.desc(),
                               Announcement.created_at.desc())
                     .all())
    return render_template('announcements.html', announcements=announcements)


@app.route('/edit_announcement/<int:announcement_id>', methods=['GET', 'POST'])
@login_required
def edit_announcement(announcement_id):
    """编辑公告"""
    announcement = Announcement.query.get_or_404(announcement_id)
    if request.method == 'POST':
        announcement.title = request.form.get('title')
        announcement.content = request.form.get('content')
        announcement.priority = int(request.form.get('priority', 0))
        announcement.updated_at = datetime.now()
        db.session.commit()
        flash('公告已更新', 'success')
        return redirect(url_for('manage_announcements'))
    return render_template('edit_announcement.html', announcement=announcement)
