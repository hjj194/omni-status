"""GPU 报告 Blueprint 路由 —— 仅薄薄一层,业务逻辑都在 queries / detail 模块。"""
from flask import Blueprint, render_template, jsonify, request, abort

from auth import login_required

from .detail import get_machine_detail
from .llm_agent import render_markdown_safe
from .models import LlmReport
from .queries import (
    get_summary_stats,
    get_idle_gpus,
    get_heatmap_data,
    get_longterm_idle,
    get_error_gpus,
)

gpu_report_bp = Blueprint('gpu_report', __name__,
                          url_prefix='/gpu-report',
                          template_folder='templates')


@gpu_report_bp.route('/')
@login_required
def report_page():
    latest_ok = (LlmReport.query
                 .filter_by(status='ok')
                 .order_by(LlmReport.generated_at.desc())
                 .first())
    latest_html = render_markdown_safe(latest_ok.content) if latest_ok else None

    history_rows = (LlmReport.query
                    .order_by(LlmReport.generated_at.desc())
                    .limit(12).all())
    history = [
        {
            'generated_at': r.generated_at,
            'status': r.status,
            'html': render_markdown_safe(r.content) if r.status == 'ok' else None,
            'error': r.content if r.status == 'error' else None,
        }
        for r in history_rows
    ]

    return render_template(
        'gpu_report.html',
        summary_stats=get_summary_stats(),
        idle_gpus=get_idle_gpus(),
        heatmap=get_heatmap_data(days=7),
        longterm_idle=get_longterm_idle(),
        error_gpus=get_error_gpus(),
        latest_summary=latest_ok,
        latest_summary_html=latest_html,
        history=history,
    )


@gpu_report_bp.route('/api/heatmap.json')
@login_required
def api_heatmap():
    try:
        days = int(request.args.get('days', 7))
        days = max(1, min(days, 90))
    except (ValueError, TypeError):
        days = 7
    return jsonify(get_heatmap_data(days=days))


@gpu_report_bp.route('/api/idle.json')
@login_required
def api_idle():
    from datetime import datetime
    return jsonify({'timestamp': datetime.now().isoformat(),
                    'idle_gpus': get_idle_gpus()})


@gpu_report_bp.route('/detail/<client_id>')
@gpu_report_bp.route('/detail/<client_id>/<int:gpu_index>')
@login_required
def detail_page(client_id, gpu_index=None):
    detail = get_machine_detail(client_id, gpu_index=gpu_index, days=7)
    if detail is None:
        abort(404)
    return render_template('gpu_detail.html', detail=detail)


@gpu_report_bp.route('/api/detail/<client_id>.json')
@gpu_report_bp.route('/api/detail/<client_id>/<int:gpu_index>.json')
@login_required
def api_detail(client_id, gpu_index=None):
    try:
        days = max(1, min(int(request.args.get('days', 7)), 90))
    except (ValueError, TypeError):
        days = 7
    detail = get_machine_detail(client_id, gpu_index=gpu_index, days=days)
    if detail is None:
        return jsonify({'error': 'client not found'}), 404
    return jsonify(detail)
