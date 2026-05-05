#!/bin/bash
# migrate.sh — omni-status 分支迁移工具
# 用途: 在已部署的服务端/客户端之间切换分支，保留数据库和配置，支持一键回退
#
# 用法:
#   sudo ./migrate.sh                  # 交互式菜单
#   sudo OMNI_TO=main ./migrate.sh     # 指定目标分支（跳过选择）

set -euo pipefail

# ─── 颜色 ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

# ─── 常量 ──────────────────────────────────────────────────────────────────
REPO_URL="https://github.com/hjj194/omni-status.git"
DEFAULT_FROM="main"
DEFAULT_TO="0426"

SERVER_INSTALL_DIR="/opt/system-monitor/server"
CLIENT_INSTALL_DIR="/opt/system-monitor/client"
SERVER_CONFIG="/etc/system-monitor/server/server.conf"
CLIENT_CONFIG="/etc/system-monitor/client.conf"
SERVER_SERVICE="system-monitor-server"
CLIENT_SERVICE="system-monitor-client"
BACKUP_BASE="/opt/system-monitor/backups"
TEMP_DIR="/tmp/omni-migrate-$$"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="${BACKUP_BASE}/${TIMESTAMP}"

# ─── 工具函数 ────────────────────────────────────────────────────────────────
pm() {
    case $1 in
        ok)   echo -e "${GREEN}✓ $2${NC}" ;;
        err)  echo -e "${RED}✗ $2${NC}" ;;
        warn) echo -e "${YELLOW}! $2${NC}" ;;
        info) echo -e "${CYAN}i $2${NC}" ;;
        *)    echo -e "$2" ;;
    esac
}

header() {
    clear
    echo -e "${BLUE}══════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}        omni-status 分支迁移工具                  ${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════${NC}"
    echo ""
}

check_root() {
    [ "$(id -u)" -eq 0 ] || { pm err "请以 root 权限运行: sudo $0"; exit 1; }
}

service_running() {
    systemctl is-active --quiet "$1" 2>/dev/null
}

# ─── 分支选择 ────────────────────────────────────────────────────────────────
select_target_branch() {
    # 环境变量优先
    if [ -n "${OMNI_TO:-}" ]; then
        TARGET_BRANCH="$OMNI_TO"
        pm info "目标分支 (来自环境变量): $TARGET_BRANCH"
        return
    fi

    pm info "正在获取远程分支列表..."
    local branches=()
    local raw=""
    if command -v git &>/dev/null; then
        raw=$(git ls-remote --heads "$REPO_URL" 2>/dev/null \
            | awk -F'/' '{print $NF}' | sort) || raw=""
    fi

    if [ -n "$raw" ]; then
        while IFS= read -r b; do [ -n "$b" ] && branches+=("$b"); done <<< "$raw"
        echo ""
        echo -e "${CYAN}可用分支:${NC}"
        local i=1 default_idx=1
        for b in "${branches[@]}"; do
            [ "$b" = "$DEFAULT_TO" ] && { echo -e "  $i) ${GREEN}$b${NC}  ← 默认"; default_idx=$i; } \
                                     || echo "  $i) $b"
            ((i++))
        done
        echo ""
        local choice
        read -p "请选择目标分支编号 [默认 ${branches[$((default_idx-1))]}]: " choice
        if [ -z "$choice" ]; then
            TARGET_BRANCH="${branches[$((default_idx-1))]}"
        elif [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#branches[@]}" ]; then
            TARGET_BRANCH="${branches[$((choice-1))]}"
        else
            pm warn "无效输入，使用默认: ${branches[$((default_idx-1))]}"; TARGET_BRANCH="${branches[$((default_idx-1))]}"
        fi
    else
        pm warn "无法获取分支列表，请手动输入"
        read -p "目标分支 [默认: $DEFAULT_TO]: " manual; TARGET_BRANCH="${manual:-$DEFAULT_TO}"
    fi

    pm ok "目标分支: $TARGET_BRANCH"
    echo ""
}

# ─── 拉取目标分支代码 ─────────────────────────────────────────────────────────
fetch_code() {
    pm info "克隆分支 $TARGET_BRANCH ..."
    rm -rf "$TEMP_DIR"
    mkdir -p "$TEMP_DIR"

    if ! command -v git &>/dev/null; then
        pm warn "未找到 git，尝试安装..."
        apt-get update -qq && apt-get install -y git || { pm err "git 安装失败"; return 1; }
    fi

    git clone --branch "$TARGET_BRANCH" --depth 1 "$REPO_URL" "$TEMP_DIR" \
        && pm ok "克隆完成" || { pm err "克隆失败"; return 1; }
}

# ─── 备份 ────────────────────────────────────────────────────────────────────
backup_server() {
    pm info "备份服务端..."
    local bdir="${BACKUP_DIR}/server"
    mkdir -p "$bdir"

    # 代码
    rsync -a --exclude='venv/' --exclude='__pycache__/' \
        "$SERVER_INSTALL_DIR/" "$bdir/code/"
    # 数据库
    local db="${SERVER_INSTALL_DIR}/monitor.db"
    [ -f "$db" ] && cp "$db" "$bdir/monitor.db" && pm ok "数据库已备份"
    # INI 配置
    [ -f "$SERVER_CONFIG" ] && cp "$SERVER_CONFIG" "$bdir/server.conf" && pm ok "server.conf 已备份"
    # runtime_settings.json（LLM 配置 + API Key，gitignored，必须单独备份）
    local rs="${SERVER_INSTALL_DIR}/runtime_settings.json"
    [ -f "$rs" ] && cp "$rs" "$bdir/runtime_settings.json" && pm ok "runtime_settings.json 已备份"
    # server_config.json（管理面板覆盖项，gitignored）
    local sc="${SERVER_INSTALL_DIR}/server_config.json"
    [ -f "$sc" ] && cp "$sc" "$bdir/server_config.json" && pm ok "server_config.json 已备份"

    echo "$TARGET_BRANCH" > "${BACKUP_DIR}/target_branch"
    pm ok "服务端备份完成 → $bdir"
}

backup_client() {
    pm info "备份客户端..."
    local bdir="${BACKUP_DIR}/client"
    mkdir -p "$bdir"

    rsync -a --exclude='venv/' --exclude='__pycache__/' \
        "$CLIENT_INSTALL_DIR/" "$bdir/code/"
    [ -f "$CLIENT_CONFIG" ] && cp "$CLIENT_CONFIG" "$bdir/client.conf" && pm ok "配置已备份"

    echo "$TARGET_BRANCH" > "${BACKUP_DIR}/target_branch"
    pm ok "客户端备份完成 → $bdir"
}

# ─── 迁移服务端 ───────────────────────────────────────────────────────────────
migrate_server() {
    header
    echo -e "${CYAN}迁移服务端${NC}\n"

    [ -d "$SERVER_INSTALL_DIR" ] || { pm err "服务端未安装"; read -rp "按回车继续..."; return; }
    [ -d "$TEMP_DIR/server" ]   || { pm err "未找到目标分支的 server/ 目录"; read -rp "按回车继续..."; return; }

    backup_server

    # 停服务
    local was_running=false
    service_running "$SERVER_SERVICE" && { systemctl stop "$SERVER_SERVICE"; was_running=true; pm ok "服务已停止"; }

    # 替换代码
    # 排除项说明:
    #   venv/               — Python 虚拟环境，重建成本高且与平台绑定
    #   monitor.db          — 业务数据库，由 flask db upgrade 处理 schema 演进
    #   runtime_settings.json — 管理员面板写入的 LLM 配置（含 API Key），gitignored
    #   server_config.json  — 管理员面板写入的服务配置覆盖，gitignored
    #   __pycache__/        — 编译缓存，自动重建
    pm info "替换代码文件..."
    rsync -a --delete \
        --exclude='venv/' \
        --exclude='monitor.db' \
        --exclude='runtime_settings.json' \
        --exclude='server_config.json' \
        --exclude='__pycache__/' \
        "$TEMP_DIR/server/" "$SERVER_INSTALL_DIR/"

    # 恢复 INI 配置（rsync 可能已覆盖 /etc 下的软链接或同步文件）
    local bdir="${BACKUP_DIR}/server"
    [ -f "$bdir/server.conf" ] && { mkdir -p "$(dirname "$SERVER_CONFIG")"; cp "$bdir/server.conf" "$SERVER_CONFIG"; }

    # 如果是首次迁移到 0426（runtime_settings.json 不存在），创建空白默认值
    # 避免服务启动时因文件缺失报错，同时不覆盖已有配置
    local rs_file="${SERVER_INSTALL_DIR}/runtime_settings.json"
    if [ ! -f "$rs_file" ]; then
        cat > "$rs_file" << 'EOF'
{
  "retention_days": 7,
  "llm_report_retention": 12,
  "llm_provider": "",
  "llm_model": "",
  "llm_base_url": "",
  "llm_api_key": "",
  "llm_schedule_cron": "0 9 * * 1"
}
EOF
        pm info "已创建空白 runtime_settings.json（LLM 功能需在管理面板配置）"
    else
        pm ok "已保留现有 runtime_settings.json（LLM 配置完整）"
    fi
    # 无论新建还是保留，都强制 600 权限（含 API Key 的敏感文件）
    chmod 600 "$rs_file"

    # 更新 pip 包
    pm info "更新 Python 依赖..."
    if [ -f "$SERVER_INSTALL_DIR/requirements.txt" ]; then
        "$SERVER_INSTALL_DIR/venv/bin/pip" install -q -r "$SERVER_INSTALL_DIR/requirements.txt"
        pm ok "依赖更新完成"
    fi

    # 数据库 schema 迁移
    local migrations_dir="$SERVER_INSTALL_DIR/migrations"
    if [ -d "$migrations_dir" ]; then
        pm info "执行数据库迁移 (flask db upgrade)..."
        cd "$SERVER_INSTALL_DIR"
        FLASK_APP=server.py "$SERVER_INSTALL_DIR/venv/bin/flask" db upgrade 2>&1 \
            && pm ok "数据库迁移完成" \
            || pm warn "flask db upgrade 失败，请手动检查（服务将照常启动）"
    fi

    # 启动服务并验证
    if [ "$was_running" = true ]; then
        systemctl start "$SERVER_SERVICE"
        sleep 2
        if ! service_running "$SERVER_SERVICE"; then
            pm err "服务启动失败！运行自动回退..."
            rollback_from "$BACKUP_DIR" server
            echo ""
            pm err "服务端迁移失败，已回退至原状态"
            pm info "失败备份保留: $BACKUP_DIR （供调查用）"
            pm info "查看日志: journalctl -u $SERVER_SERVICE -n 50"
            echo ""
            read -rp "按回车继续..."
            return 1
        fi
        pm ok "服务端已启动"
    fi

    echo ""
    pm ok "服务端已迁移至分支: $TARGET_BRANCH"
    pm info "备份保存于: $BACKUP_DIR"
    echo ""
    # 迁移后提示：0426 新增的需手动配置项
    echo -e "${YELLOW}─── 迁移后待配置项 ───────────────────────────────────${NC}"

    # 检查服务端是否已配置 report_token
    local token_configured=false
    if [ -f "$SERVER_CONFIG" ] && grep -q "^report_token\s*=\s*..\+" "$SERVER_CONFIG" 2>/dev/null; then
        token_configured=true
    fi

    echo -e "  ${CYAN}客户端上报鉴权 (report_token)${NC}:"
    if [ "$token_configured" = true ]; then
        # 从 server.conf 读出实际 token 值，醒目展示供复制
        local current_token
        current_token=$(grep "^report_token" "$SERVER_CONFIG" | sed 's/.*=\s*//' | tr -d '[:space:]')
        echo ""
        echo -e "${YELLOW}╔══════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║          客户端上报鉴权 Token (report_token)         ║${NC}"
        echo -e "${YELLOW}╠══════════════════════════════════════════════════════╣${NC}"
        echo -e "${YELLOW}║  ${GREEN}${current_token}${YELLOW}  ║${NC}"
        echo -e "${YELLOW}╠══════════════════════════════════════════════════════╣${NC}"
        echo -e "${YELLOW}║  在每台客户端迁移时，在提示处粘贴此 Token           ║${NC}"
        echo -e "${YELLOW}╚══════════════════════════════════════════════════════╝${NC}"
    else
        echo "    当前未启用（如需启用，可在迁移后于 server.conf 添加 report_token）"
        read -p "    是否现在生成并启用 report_token? (y/n) [n]: " gen_token
        if [ "$gen_token" = "y" ]; then
            local new_token; new_token=$(openssl rand -hex 16)
            # 追加到 server.conf
            echo "report_token = $new_token" >> "$SERVER_CONFIG"
            systemctl restart "$SERVER_SERVICE" 2>/dev/null || true
            echo ""
            echo -e "${YELLOW}╔══════════════════════════════════════════════════════╗${NC}"
            echo -e "${YELLOW}║          客户端上报鉴权 Token (report_token)         ║${NC}"
            echo -e "${YELLOW}╠══════════════════════════════════════════════════════╣${NC}"
            echo -e "${YELLOW}║  ${GREEN}${new_token}${YELLOW}  ║${NC}"
            echo -e "${YELLOW}╠══════════════════════════════════════════════════════╣${NC}"
            echo -e "${YELLOW}║  在每台客户端迁移时，在提示处粘贴此 Token           ║${NC}"
            echo -e "${YELLOW}╚══════════════════════════════════════════════════════╝${NC}"
        fi
    fi

    echo ""
    echo -e "  ${CYAN}LLM 周报${NC}（如需启用）:"
    echo "    登录管理面板 → 设置 → LLM 配置"
    echo "    填写: Provider / Model / API Key / Base URL"
    echo -e "${YELLOW}──────────────────────────────────────────────────────${NC}"
    echo ""
    read -rp "按回车继续..."
}

# ─── 迁移客户端 ───────────────────────────────────────────────────────────────
migrate_client() {
    header
    echo -e "${CYAN}迁移客户端${NC}\n"

    [ -d "$CLIENT_INSTALL_DIR" ] || { pm err "客户端未安装"; read -rp "按回车继续..."; return; }
    [ -d "$TEMP_DIR/client" ]   || { pm err "未找到目标分支的 client/ 目录"; read -rp "按回车继续..."; return; }

    backup_client

    local was_running=false
    service_running "$CLIENT_SERVICE" && { systemctl stop "$CLIENT_SERVICE"; was_running=true; pm ok "服务已停止"; }

    pm info "替换代码文件..."
    rsync -a --delete \
        --exclude='venv/' \
        --exclude='__pycache__/' \
        "$TEMP_DIR/client/" "$CLIENT_INSTALL_DIR/"

    # 恢复配置
    local bdir="${BACKUP_DIR}/client"
    [ -f "$bdir/client.conf" ] && cp "$bdir/client.conf" "$CLIENT_CONFIG"

    # 询问是否更新/设置 report_token
    echo ""
    local current_token=""
    [ -f "$CLIENT_CONFIG" ] && current_token=$(grep "^report_token" "$CLIENT_CONFIG" 2>/dev/null | sed 's/.*=\s*//' | tr -d '[:space:]' || true)

    if [ -n "$current_token" ]; then
        pm info "当前 report_token: ${current_token}"
        read -p "是否更新 report_token? (y/n) [n]: " update_token
    else
        pm info "若服务端启用了 report_token，请在此粘贴；否则直接回车跳过"
        update_token="y"
    fi

    if [ "$update_token" = "y" ]; then
        local new_token=""
        read -p "report_token (留空跳过): " new_token
        if [ -n "$new_token" ]; then
            # 写入或更新 client.conf 中的 report_token
            if grep -q "^report_token" "$CLIENT_CONFIG" 2>/dev/null; then
                sed -i "s/^report_token\s*=.*/report_token = ${new_token}/" "$CLIENT_CONFIG"
            else
                echo "report_token = ${new_token}" >> "$CLIENT_CONFIG"
            fi
            pm ok "report_token 已更新"
        fi
    fi

    pm info "更新 Python 依赖..."
    if [ -f "$CLIENT_INSTALL_DIR/requirements.txt" ]; then
        "$CLIENT_INSTALL_DIR/venv/bin/pip" install -q -r "$CLIENT_INSTALL_DIR/requirements.txt"
        pm ok "依赖更新完成"
    fi

    if [ "$was_running" = true ]; then
        systemctl start "$CLIENT_SERVICE"
        sleep 2
        if ! service_running "$CLIENT_SERVICE"; then
            pm err "服务启动失败！运行自动回退..."
            rollback_from "$BACKUP_DIR" client
            echo ""
            pm err "客户端迁移失败，已回退至原状态"
            pm info "失败备份保留: $BACKUP_DIR （供调查用）"
            pm info "查看日志: journalctl -u $CLIENT_SERVICE -n 50"
            echo ""
            read -rp "按回车继续..."
            return 1
        fi
        pm ok "客户端已启动"
    fi

    echo ""
    pm ok "客户端已迁移至分支: $TARGET_BRANCH"
    pm info "备份保存于: $BACKUP_DIR"
    echo ""
    read -rp "按回车继续..."
}

# ─── 回退核心逻辑 ─────────────────────────────────────────────────────────────
rollback_from() {
    local bdir="$1"   # 备份目录路径
    local target="$2" # server | client | both

    if [[ "$target" == "server" || "$target" == "both" ]] && [ -d "$bdir/server" ]; then
        pm info "回退服务端代码..."
        service_running "$SERVER_SERVICE" && systemctl stop "$SERVER_SERVICE"

        rsync -a --delete \
            --exclude='venv/' \
            --exclude='monitor.db' \
            --exclude='__pycache__/' \
            "$bdir/server/code/" "$SERVER_INSTALL_DIR/"

        # 恢复数据库
        [ -f "$bdir/server/monitor.db" ] && {
            cp "$bdir/server/monitor.db" "$SERVER_INSTALL_DIR/monitor.db"
            pm ok "数据库已恢复"
        }
        # 恢复 INI 配置
        [ -f "$bdir/server/server.conf" ] && {
            mkdir -p "$(dirname "$SERVER_CONFIG")"
            cp "$bdir/server/server.conf" "$SERVER_CONFIG"
        }
        # 恢复 runtime_settings.json（LLM 配置 + API Key）
        [ -f "$bdir/server/runtime_settings.json" ] && {
            cp "$bdir/server/runtime_settings.json" "$SERVER_INSTALL_DIR/runtime_settings.json"
            chmod 600 "$SERVER_INSTALL_DIR/runtime_settings.json"
            pm ok "runtime_settings.json 已恢复"
        }
        # 恢复 server_config.json
        [ -f "$bdir/server/server_config.json" ] && {
            cp "$bdir/server/server_config.json" "$SERVER_INSTALL_DIR/server_config.json"
        }
        # 恢复 pip 包
        [ -f "$SERVER_INSTALL_DIR/requirements.txt" ] && \
            "$SERVER_INSTALL_DIR/venv/bin/pip" install -q -r "$SERVER_INSTALL_DIR/requirements.txt"

        systemctl start "$SERVER_SERVICE"
        sleep 2
        service_running "$SERVER_SERVICE" \
            && pm ok "服务端回退成功" || pm err "服务端回退后仍无法启动，请手动检查"
    fi

    if [[ "$target" == "client" || "$target" == "both" ]] && [ -d "$bdir/client" ]; then
        pm info "回退客户端代码..."
        service_running "$CLIENT_SERVICE" && systemctl stop "$CLIENT_SERVICE"

        rsync -a --delete \
            --exclude='venv/' \
            --exclude='__pycache__/' \
            "$bdir/client/code/" "$CLIENT_INSTALL_DIR/"

        [ -f "$bdir/client/client.conf" ] && cp "$bdir/client/client.conf" "$CLIENT_CONFIG"
        [ -f "$CLIENT_INSTALL_DIR/requirements.txt" ] && \
            "$CLIENT_INSTALL_DIR/venv/bin/pip" install -q -r "$CLIENT_INSTALL_DIR/requirements.txt"

        systemctl start "$CLIENT_SERVICE"
        sleep 2
        service_running "$CLIENT_SERVICE" \
            && pm ok "客户端回退成功" || pm err "客户端回退后仍无法启动，请手动检查"
    fi
}

# ─── 交互式回退菜单 ───────────────────────────────────────────────────────────
do_rollback() {
    header
    echo -e "${YELLOW}回退到历史版本${NC}\n"

    # 列出所有备份
    local backups=()
    if [ -d "$BACKUP_BASE" ]; then
        while IFS= read -r d; do
            [ -d "$d" ] && backups+=("$d")
        done < <(find "$BACKUP_BASE" -mindepth 1 -maxdepth 1 -type d | sort -r)
    fi

    if [ ${#backups[@]} -eq 0 ]; then
        pm warn "未找到任何备份 (备份目录: $BACKUP_BASE)"
        read -rp "按回车继续..."; return
    fi

    echo -e "${CYAN}可用备份:${NC}"
    local i=1
    for bdir in "${backups[@]}"; do
        local ts; ts=$(basename "$bdir")
        local has_server=""; local has_client=""
        [ -d "$bdir/server" ] && has_server=" [服务端]"
        [ -d "$bdir/client" ] && has_client=" [客户端]"
        local tbranch=""
        [ -f "$bdir/target_branch" ] && tbranch=" (迁移至: $(cat "$bdir/target_branch"))"
        echo "  $i) $ts$has_server$has_client$tbranch"
        ((i++))
    done
    echo ""

    local choice
    read -p "请选择备份编号 (0 取消): " choice
    [[ "$choice" == "0" || -z "$choice" ]] && return
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt "${#backups[@]}" ]; then
        pm err "无效选择"; read -rp "按回车继续..."; return
    fi

    local selected="${backups[$((choice-1))]}"
    local has_s=false; local has_c=false
    [ -d "$selected/server" ] && has_s=true
    [ -d "$selected/client" ] && has_c=true

    echo ""
    pm warn "将从备份 $(basename "$selected") 恢复，当前运行中的代码将被替换"

    local target="both"
    if [ "$has_s" = true ] && [ "$has_c" = true ]; then
        echo "1) 仅回退服务端"
        echo "2) 仅回退客户端"
        echo "3) 两者都回退"
        read -p "请选择 [3]: " sub; sub=${sub:-3}
        case $sub in
            1) target="server" ;; 2) target="client" ;; *) target="both" ;;
        esac
    elif [ "$has_s" = true ]; then
        target="server"
    else
        target="client"
    fi

    read -p "确认回退? (yes/n): " confirm
    [ "$confirm" = "yes" ] || { pm info "已取消"; read -rp "按回车继续..."; return; }

    echo ""
    rollback_from "$selected" "$target"
    echo ""
    read -rp "按回车继续..."
}

# ─── 迁移入口（含拉取代码） ────────────────────────────────────────────────────
run_migration() {
    local what="$1"  # server | client | both

    select_target_branch

    # 确认
    echo -e "${YELLOW}即将迁移到分支: ${GREEN}$TARGET_BRANCH${NC}"
    pm warn "迁移前会自动备份，失败时可一键回退"
    read -p "确认继续? (yes/n): " confirm
    [ "$confirm" = "yes" ] || { pm info "已取消"; return; }
    echo ""

    fetch_code

    mkdir -p "$BACKUP_DIR"

    case "$what" in
        server) migrate_server || true ;;
        client) migrate_client || true ;;
        both)
            # 服务端迁移失败（已自动回退）则不再迁移客户端，避免版本错配
            if migrate_server; then
                migrate_client || true
            else
                pm warn "服务端迁移失败，跳过客户端迁移以避免版本不匹配"
                read -rp "按回车继续..."
            fi
            ;;
    esac

    rm -rf "$TEMP_DIR"
}

# ─── 状态概览 ────────────────────────────────────────────────────────────────
show_status() {
    header
    echo -e "${CYAN}当前安装状态${NC}\n"

    for role in server client; do
        local idir; [ "$role" = "server" ] && idir="$SERVER_INSTALL_DIR" || idir="$CLIENT_INSTALL_DIR"
        local svc;  [ "$role" = "server" ] && svc="$SERVER_SERVICE"       || svc="$CLIENT_SERVICE"
        local label; [ "$role" = "server" ] && label="服务端" || label="客户端"

        if [ -d "$idir" ]; then
            local status_str
            service_running "$svc" \
                && status_str="${GREEN}运行中${NC}" \
                || status_str="${RED}已停止${NC}"
            echo -e "  $label: 已安装  状态: $status_str"
        else
            echo -e "  $label: ${YELLOW}未安装${NC}"
        fi
    done

    echo ""
    local backup_count=0
    [ -d "$BACKUP_BASE" ] && backup_count=$(find "$BACKUP_BASE" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
    pm info "可用备份: $backup_count 个 (保存于 $BACKUP_BASE)"
    echo ""
    read -rp "按回车继续..."
}

# ─── 备份清理 ────────────────────────────────────────────────────────────────
cleanup_backups() {
    header
    echo -e "${YELLOW}清理历史备份${NC}\n"

    if [ ! -d "$BACKUP_BASE" ]; then
        pm info "尚无任何备份 (备份目录: $BACKUP_BASE)"
        read -rp "按回车继续..."; return
    fi

    # 收集所有备份，按时间倒序
    local backups=()
    while IFS= read -r d; do
        [ -d "$d" ] && backups+=("$d")
    done < <(find "$BACKUP_BASE" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -r)

    if [ ${#backups[@]} -eq 0 ]; then
        pm info "尚无任何备份"
        read -rp "按回车继续..."; return
    fi

    # 展示全部备份及其大小
    local total_size; total_size=$(du -sh "$BACKUP_BASE" 2>/dev/null | awk '{print $1}')
    echo -e "${CYAN}当前备份 (${#backups[@]} 个, 共 ${total_size}):${NC}"
    local i=1
    for bdir in "${backups[@]}"; do
        local ts; ts=$(basename "$bdir")
        local size; size=$(du -sh "$bdir" 2>/dev/null | awk '{print $1}')
        local has_s=""; local has_c=""
        [ -d "$bdir/server" ] && has_s=" [服务端]"
        [ -d "$bdir/client" ] && has_c=" [客户端]"
        echo "  $i) $ts  (${size})${has_s}${has_c}"
        ((i++))
    done
    echo ""

    echo -e "${CYAN}清理策略:${NC}"
    echo "  1) 保留最近 N 个，删除其余"
    echo "  2) 删除 N 天前的"
    echo "  3) 删除指定备份"
    echo "  0) 返回"
    echo ""
    local strategy
    read -rp "请选择策略: " strategy

    local to_delete=()
    case "$strategy" in
        1)
            local keep_n
            read -rp "保留最近几个? [3]: " keep_n
            keep_n=${keep_n:-3}
            if ! [[ "$keep_n" =~ ^[0-9]+$ ]]; then
                pm err "无效数字"; read -rp "按回车继续..."; return
            fi
            if [ "${#backups[@]}" -le "$keep_n" ]; then
                pm info "当前备份数 (${#backups[@]}) 不超过 $keep_n，无需清理"
                read -rp "按回车继续..."; return
            fi
            local idx=0
            for bdir in "${backups[@]}"; do
                [ "$idx" -ge "$keep_n" ] && to_delete+=("$bdir")
                ((idx++))
            done
            ;;
        2)
            local days
            read -rp "删除几天前的? [30]: " days
            days=${days:-30}
            if ! [[ "$days" =~ ^[0-9]+$ ]]; then
                pm err "无效数字"; read -rp "按回车继续..."; return
            fi
            # find 用 mtime +N 表示 N 天前修改的目录
            while IFS= read -r d; do
                [ -d "$d" ] && to_delete+=("$d")
            done < <(find "$BACKUP_BASE" -mindepth 1 -maxdepth 1 -type d -mtime +"$days" 2>/dev/null)
            ;;
        3)
            local nums
            read -rp "请输入要删除的编号 (空格分隔, 如 '2 3 5'): " -a nums
            for n in "${nums[@]}"; do
                if [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -ge 1 ] && [ "$n" -le "${#backups[@]}" ]; then
                    to_delete+=("${backups[$((n-1))]}")
                else
                    pm warn "跳过无效编号: $n"
                fi
            done
            ;;
        0|"") return ;;
        *) pm err "无效选择"; read -rp "按回车继续..."; return ;;
    esac

    if [ "${#to_delete[@]}" -eq 0 ]; then
        pm info "没有匹配的备份可删除"
        read -rp "按回车继续..."; return
    fi

    # 列出待删除项 + 确认
    echo ""
    pm warn "以下 ${#to_delete[@]} 个备份将被删除:"
    local del_size_total=0
    for bdir in "${to_delete[@]}"; do
        local sz; sz=$(du -sh "$bdir" 2>/dev/null | awk '{print $1}')
        echo "  - $(basename "$bdir") (${sz})"
    done
    echo ""
    read -rp "确认删除? (yes/n): " confirm
    [ "$confirm" = "yes" ] || { pm info "已取消"; read -rp "按回车继续..."; return; }

    for bdir in "${to_delete[@]}"; do
        rm -rf "$bdir" && pm ok "已删除: $(basename "$bdir")" || pm err "删除失败: $bdir"
    done

    echo ""
    local new_total; new_total=$(du -sh "$BACKUP_BASE" 2>/dev/null | awk '{print $1}')
    pm ok "清理完成，剩余备份占用: ${new_total}"
    read -rp "按回车继续..."
}

# ─── 主菜单 ──────────────────────────────────────────────────────────────────
show_menu() {
    while true; do
        header
        echo "请选择操作:"
        echo ""
        echo -e "${GREEN}迁移${NC}"
        echo "1) 迁移服务端"
        echo "2) 迁移客户端"
        echo "3) 迁移服务端 + 客户端"
        echo ""
        echo -e "${YELLOW}回退${NC}"
        echo "4) 回退到历史版本"
        echo ""
        echo -e "${CYAN}信息与维护${NC}"
        echo "5) 查看当前状态"
        echo "6) 清理历史备份"
        echo ""
        echo "0) 退出"
        echo ""
        read -rp "请输入选项: " choice
        case $choice in
            1) run_migration server ;;
            2) run_migration client ;;
            3) run_migration both   ;;
            4) do_rollback         ;;
            5) show_status         ;;
            6) cleanup_backups     ;;
            0) pm info "退出"; exit 0 ;;
            *) pm err "无效选项"; sleep 1 ;;
        esac
    done
}

# ─── 清理 ────────────────────────────────────────────────────────────────────
cleanup() { rm -rf "$TEMP_DIR"; }
trap cleanup EXIT

# ─── 入口 ────────────────────────────────────────────────────────────────────
check_root
show_menu
