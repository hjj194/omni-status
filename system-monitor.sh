#!/bin/bash
# System Monitor - Management Script
# 系统监控管理脚本

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default Git repository URL
DEFAULT_REPO_URL="https://github.com/hjj194/omni-status.git"
DEFAULT_BRANCH="main"

# Configuration paths
SERVER_INSTALL_DIR="/opt/system-monitor/server"
CLIENT_INSTALL_DIR="/opt/system-monitor/client"
SERVER_CONFIG_DIR="/etc/system-monitor/server"
CLIENT_CONFIG_DIR="/etc/system-monitor/client"
SERVER_SERVICE="system-monitor-server"
CLIENT_SERVICE="system-monitor-client"
SERVER_CONFIG="${SERVER_CONFIG_DIR}/server.conf"
CLIENT_CONFIG="${CLIENT_CONFIG_DIR}/client.conf"
LOG_DIR="/var/log/system-monitor"
TEMP_DIR="/tmp/system-monitor-temp"

# Function to print colored section headers
print_header() {
    clear
    echo -e "${BLUE}══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}              系统监控管理工具 v1.0.0                    ${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Function to print colored messages
print_message() {
    local type=$1
    local message=$2
    
    case $type in
        "success") echo -e "${GREEN}✓ $message${NC}" ;;
        "error") echo -e "${RED}✗ $message${NC}" ;;
        "warning") echo -e "${YELLOW}! $message${NC}" ;;
        "info") echo -e "${CYAN}i $message${NC}" ;;
        *) echo -e "$message" ;;
    esac
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if the script is running as root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        print_message "error" "此脚本需要以root权限运行"
        print_message "info" "请使用 'sudo $0' 重新运行"
        exit 1
    fi
}

# Function to identify the Linux distribution
identify_distro() {
    if command_exists apt-get; then
        echo "debian"
    elif command_exists yum; then
        echo "rhel"
    else
        echo "unknown"
    fi
}

# Function to clone the repository
clone_repository() {
    local repo_url=$1
    local branch=$2
    
    print_message "info" "正在克隆仓库 $repo_url (分支: $branch)..."
    
    # Make sure the temporary directory does not exist
    rm -rf "$TEMP_DIR"
    mkdir -p "$TEMP_DIR"
    
    if ! command_exists git; then
        print_message "warning" "Git未安装，正在安装..."
        local distro=$(identify_distro)
        if [ "$distro" = "debian" ]; then
            apt-get update && apt-get install -y git
        elif [ "$distro" = "rhel" ]; then
            yum -y install git
        else
            print_message "error" "无法自动安装Git。请手动安装Git后重试。"
            return 1
        fi
    fi
    
    # Clone the repository
    if git clone --branch "$branch" --depth 1 "$repo_url" "$TEMP_DIR"; then
        print_message "success" "仓库克隆成功"
        return 0
    else
        print_message "error" "仓库克隆失败"
        return 1
    fi
}

# Function to install server
install_server() {
    print_header
    echo -e "${CYAN}正在安装服务端...${NC}\n"
    
    # Check if already installed
    if [ -d "$SERVER_INSTALL_DIR" ]; then
        print_message "warning" "服务端已经安装。如需重新安装，请先卸载。"
        read -p "按回车键继续..."
        return
    fi
    
    local distro=$(identify_distro)
    
    # Install dependencies
    if [ "$distro" = "debian" ]; then
        print_message "info" "正在安装依赖包..."
        apt-get update
        apt-get install -y python3 python3-pip python3-venv sqlite3
    elif [ "$distro" = "rhel" ]; then
        print_message "info" "正在安装依赖包..."
        yum -y update
        yum -y install python3 python3-pip sqlite3
    else
        print_message "error" "不支持的Linux发行版。"
        print_message "info" "请手动安装以下包: python3, python3-pip, sqlite3"
        read -p "按回车键继续..."
        return
    fi
    
    # Create directories
    print_message "info" "创建目录..."
    mkdir -p "$SERVER_INSTALL_DIR"
    mkdir -p "$SERVER_CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    
    # Ask for Git repository information or use defaults
    local repo_url
    local branch
    
    read -p "请输入Git仓库URL [$DEFAULT_REPO_URL]: " repo_url
    repo_url=${repo_url:-$DEFAULT_REPO_URL}
    
    read -p "请输入分支名称 [$DEFAULT_BRANCH]: " branch
    branch=${branch:-$DEFAULT_BRANCH}
    
    # Clone the repository
    if ! clone_repository "$repo_url" "$branch"; then
        print_message "error" "无法获取源代码，安装失败"
        read -p "按回车键继续..."
        return
    fi
    
    # Copy server files
    print_message "info" "复制服务端文件..."
    if [ -d "$TEMP_DIR/server" ]; then
        cp -r "$TEMP_DIR/server"/* "$SERVER_INSTALL_DIR/"
        chmod +x "$SERVER_INSTALL_DIR/server.py"
        print_message "success" "服务端文件复制完成"
    else
        print_message "error" "在仓库中未找到服务端文件夹"
        read -p "按回车键继续..."
        return
    fi
    
    # Set up Python virtual environment
    print_message "info" "设置Python虚拟环境..."
    python3 -m venv "$SERVER_INSTALL_DIR/venv"
    source "$SERVER_INSTALL_DIR/venv/bin/activate"
    
    # Install Python packages
    print_message "info" "安装Python包..."
    if [ -f "$SERVER_INSTALL_DIR/requirements.txt" ]; then
        pip install -r "$SERVER_INSTALL_DIR/requirements.txt"
    else
        pip install flask flask-sqlalchemy werkzeug
    fi
    
    # Ask for server configuration
    local port
    local secret_key
    
    read -p "请输入服务器端口 [5000]: " port
    port=${port:-5000}
    
    # Generate random secret key
    secret_key=$(openssl rand -hex 16)
    
    # Create server configuration
    print_message "info" "创建服务器配置..."
    cat > "$SERVER_CONFIG" << EOF
[server]
host = 0.0.0.0
port = $port
secret_key = $secret_key
debug = false
EOF
    
    # Create systemd service
    print_message "info" "创建系统服务..."
    cat > "/etc/systemd/system/$SERVER_SERVICE.service" << EOF
[Unit]
Description=System Monitor Server
After=network.target

[Service]
User=root
WorkingDirectory=$SERVER_INSTALL_DIR
ExecStart=$SERVER_INSTALL_DIR/venv/bin/python $SERVER_INSTALL_DIR/server.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
Environment="FLASK_APP=server"
Environment="SECRET_KEY=$secret_key"

[Install]
WantedBy=multi-user.target
EOF
    
    # Enable and start service
    print_message "info" "启用并启动服务..."
    systemctl daemon-reload
    systemctl enable "$SERVER_SERVICE"
    systemctl start "$SERVER_SERVICE"
    
    print_message "success" "服务端安装完成!"
    print_message "info" "服务器地址: http://localhost:$port"
    print_message "info" "默认管理员账户: admin / admin"
    print_message "warning" "请尽快登录并修改默认密码!"
    
    read -p "按回车键继续..."
}

# Function to install client
install_client() {
    print_header
    echo -e "${CYAN}正在安装客户端...${NC}\n"
    
    # Check if already installed
    if [ -d "$CLIENT_INSTALL_DIR" ]; then
        print_message "warning" "客户端已经安装。如需重新安装，请先卸载。"
        read -p "按回车键继续..."
        return
    fi
    
    local distro=$(identify_distro)
    
    # Install dependencies
    if [ "$distro" = "debian" ]; then
        print_message "info" "正在安装依赖包..."
        apt-get update
        apt-get install -y python3 python3-pip python3-venv
    elif [ "$distro" = "rhel" ]; then
        print_message "info" "正在安装依赖包..."
        yum -y update
        yum -y install python3 python3-pip
    else
        print_message "error" "不支持的Linux发行版。"
        print_message "info" "请手动安装以下包: python3, python3-pip"
        read -p "按回车键继续..."
        return
    fi
    
    # Create directories
    print_message "info" "创建目录..."
    mkdir -p "$CLIENT_INSTALL_DIR"
    mkdir -p "$CLIENT_CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    
    # Ask if to use the same repository as the server
    local use_same_repo
    local repo_url
    local branch
    
    # Check if we have a temporary directory with repository already
    if [ ! -d "$TEMP_DIR" ]; then
        # Ask for Git repository information or use defaults
        read -p "请输入Git仓库URL [$DEFAULT_REPO_URL]: " repo_url
        repo_url=${repo_url:-$DEFAULT_REPO_URL}
        
        read -p "请输入分支名称 [$DEFAULT_BRANCH]: " branch
        branch=${branch:-$DEFAULT_BRANCH}
        
        # Clone the repository
        if ! clone_repository "$repo_url" "$branch"; then
            print_message "error" "无法获取源代码，安装失败"
            read -p "按回车键继续..."
            return
        fi
    fi
    
    # Copy client files
    print_message "info" "复制客户端文件..."
    if [ -d "$TEMP_DIR/client" ]; then
        cp -r "$TEMP_DIR/client"/* "$CLIENT_INSTALL_DIR/"
        chmod +x "$CLIENT_INSTALL_DIR/client.py"
        print_message "success" "客户端文件复制完成"
    else
        print_message "error" "在仓库中未找到客户端文件夹"
        read -p "按回车键继续..."
        return
    fi
    
    # Set up Python virtual environment
    print_message "info" "设置Python虚拟环境..."
    python3 -m venv "$CLIENT_INSTALL_DIR/venv"
    source "$CLIENT_INSTALL_DIR/venv/bin/activate"
    
    # Install Python packages
    print_message "info" "安装Python包..."
    if [ -f "$CLIENT_INSTALL_DIR/requirements.txt" ]; then
        pip install -r "$CLIENT_INSTALL_DIR/requirements.txt"
    else
        pip install psutil requests
    fi
    
    # Ask for client configuration
    local server_url
    local report_interval
    
    read -p "请输入服务器URL [http://localhost:5000/report]: " server_url
    server_url=${server_url:-"http://localhost:5000/report"}
    
    read -p "请输入上报间隔(秒) [60]: " report_interval
    report_interval=${report_interval:-60}
    
    # Create client configuration
    print_message "info" "创建客户端配置..."
    cat > "$CLIENT_CONFIG" << EOF
[server]
url = $server_url
report_interval = $report_interval
EOF
    
    # Create systemd service
    print_message "info" "创建系统服务..."
    cat > "/etc/systemd/system/$CLIENT_SERVICE.service" << EOF
[Unit]
Description=System Monitor Client
After=network.target

[Service]
User=root
WorkingDirectory=$CLIENT_INSTALL_DIR
ExecStart=$CLIENT_INSTALL_DIR/venv/bin/python $CLIENT_INSTALL_DIR/client.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    # Enable and start service
    print_message "info" "启用并启动服务..."
    systemctl daemon-reload
    systemctl enable "$CLIENT_SERVICE"
    systemctl start "$CLIENT_SERVICE"
    
    print_message "success" "客户端安装完成!"
    print_message "info" "服务器地址: $server_url"
    print_message "info" "上报间隔: $report_interval 秒"
    
    read -p "按回车键继续..."
}

# Function to start services
start_services() {
    print_header
    echo -e "${CYAN}启动服务...${NC}\n"
    
    local selected_service
    echo "1) 启动服务端"
    echo "2) 启动客户端"
    echo "3) 启动所有服务"
    echo "0) 返回"
    echo ""
    read -p "请选择: " selected_service
    
    case $selected_service in
        1)
            if [ -f "/etc/systemd/system/$SERVER_SERVICE.service" ]; then
                systemctl start "$SERVER_SERVICE"
                print_message "success" "服务端已启动"
            else
                print_message "error" "服务端未安装"
            fi
            ;;
        2)
            if [ -f "/etc/systemd/system/$CLIENT_SERVICE.service" ]; then
                systemctl start "$CLIENT_SERVICE"
                print_message "success" "客户端已启动"
            else
                print_message "error" "客户端未安装"
            fi
            ;;
        3)
            local started=false
            if [ -f "/etc/systemd/system/$SERVER_SERVICE.service" ]; then
                systemctl start "$SERVER_SERVICE"
                print_message "success" "服务端已启动"
                started=true
            fi
            if [ -f "/etc/systemd/system/$CLIENT_SERVICE.service" ]; then
                systemctl start "$CLIENT_SERVICE"
                print_message "success" "客户端已启动"
                started=true
            fi
            if [ "$started" = false ]; then
                print_message "error" "未找到已安装的服务"
            fi
            ;;
        0)
            return
            ;;
        *)
            print_message "error" "无效的选择"
            ;;
    esac
    
    read -p "按回车键继续..."
}

# Function to stop services
stop_services() {
    print_header
    echo -e "${CYAN}停止服务...${NC}\n"
    
    local selected_service
    echo "1) 停止服务端"
    echo "2) 停止客户端"
    echo "3) 停止所有服务"
    echo "0) 返回"
    echo ""
    read -p "请选择: " selected_service
    
    case $selected_service in
        1)
            if [ -f "/etc/systemd/system/$SERVER_SERVICE.service" ]; then
                systemctl stop "$SERVER_SERVICE"
                print_message "success" "服务端已停止"
            else
                print_message "error" "服务端未安装"
            fi
            ;;
        2)
            if [ -f "/etc/systemd/system/$CLIENT_SERVICE.service" ]; then
                systemctl stop "$CLIENT_SERVICE"
                print_message "success" "客户端已停止"
            else
                print_message "error" "客户端未安装"
            fi
            ;;
        3)
            local stopped=false
            if [ -f "/etc/systemd/system/$SERVER_SERVICE.service" ]; then
                systemctl stop "$SERVER_SERVICE"
                print_message "success" "服务端已停止"
                stopped=true
            fi
            if [ -f "/etc/systemd/system/$CLIENT_SERVICE.service" ]; then
                systemctl stop "$CLIENT_SERVICE"
                print_message "success" "客户端已停止"
                stopped=true
            fi
            if [ "$stopped" = false ]; then
                print_message "error" "未找到已安装的服务"
            fi
            ;;
        0)
            return
            ;;
        *)
            print_message "error" "无效的选择"
            ;;
    esac
    
    read -p "按回车键继续..."
}

# Function to restart services
restart_services() {
    print_header
    echo -e "${CYAN}重启服务...${NC}\n"
    
    local selected_service
    echo "1) 重启服务端"
    echo "2) 重启客户端"
    echo "3) 重启所有服务"
    echo "0) 返回"
    echo ""
    read -p "请选择: " selected_service
    
    case $selected_service in
        1)
            if [ -f "/etc/systemd/system/$SERVER_SERVICE.service" ]; then
                systemctl restart "$SERVER_SERVICE"
                print_message "success" "服务端已重启"
            else
                print_message "error" "服务端未安装"
            fi
            ;;
        2)
            if [ -f "/etc/systemd/system/$CLIENT_SERVICE.service" ]; then
                systemctl restart "$CLIENT_SERVICE"
                print_message "success" "客户端已重启"
            else
                print_message "error" "客户端未安装"
            fi
            ;;
        3)
            local restarted=false
            if [ -f "/etc/systemd/system/$SERVER_SERVICE.service" ]; then
                systemctl restart "$SERVER_SERVICE"
                print_message "success" "服务端已重启"
                restarted=true
            fi
            if [ -f "/etc/systemd/system/$CLIENT_SERVICE.service" ]; then
                systemctl restart "$CLIENT_SERVICE"
                print_message "success" "客户端已重启"
                restarted=true
            fi
            if [ "$restarted" = false ]; then
                print_message "error" "未找到已安装的服务"
            fi
            ;;
        0)
            return
            ;;
        *)
            print_message "error" "无效的选择"
            ;;
    esac
    
    read -p "按回车键继续..."
}

# Function to view service status
view_status() {
    print_header
    echo -e "${CYAN}服务状态...${NC}\n"
    
    local selected_service
    echo "1) 查看服务端状态"
    echo "2) 查看客户端状态"
    echo "3) 查看所有服务状态"
    echo "0) 返回"
    echo ""
    read -p "请选择: " selected_service
    
    case $selected_service in
        1)
            if [ -f "/etc/systemd/system/$SERVER_SERVICE.service" ]; then
                echo -e "\n${YELLOW}服务端状态:${NC}\n"
                systemctl status "$SERVER_SERVICE" --no-pager
            else
                print_message "error" "服务端未安装"
            fi
            ;;
        2)
            if [ -f "/etc/systemd/system/$CLIENT_SERVICE.service" ]; then
                echo -e "\n${YELLOW}客户端状态:${NC}\n"
                systemctl status "$CLIENT_SERVICE" --no-pager
            else
                print_message "error" "客户端未安装"
            fi
            ;;
        3)
            local found=false
            if [ -f "/etc/systemd/system/$SERVER_SERVICE.service" ]; then
                echo -e "\n${YELLOW}服务端状态:${NC}\n"
                systemctl status "$SERVER_SERVICE" --no-pager
                found=true
            fi
            if [ -f "/etc/systemd/system/$CLIENT_SERVICE.service" ]; then
                echo -e "\n${YELLOW}客户端状态:${NC}\n"
                systemctl status "$CLIENT_SERVICE" --no-pager
                found=true
            fi
            if [ "$found" = false ]; then
                print_message "error" "未找到已安装的服务"
            fi
            ;;
        0)
            return
            ;;
        *)
            print_message "error" "无效的选择"
            ;;
    esac
    
    read -p "按回车键继续..."
}

# Function to view logs
view_logs() {
    print_header
    echo -e "${CYAN}查看日志...${NC}\n"
    
    local selected_log
    echo "1) 查看服务端日志"
    echo "2) 查看客户端日志"
    echo "3) 查看系统服务日志"
    echo "0) 返回"
    echo ""
    read -p "请选择: " selected_log
    
    case $selected_log in
        1)
            if [ -f "$LOG_DIR/server.log" ]; then
                echo -e "\n${YELLOW}服务端日志 (最新50行):${NC}\n"
                tail -n 50 "$LOG_DIR/server.log"
            else
                print_message "error" "服务端日志文件不存在"
            fi
            ;;
        2)
            if [ -f "$LOG_DIR/client.log" ]; then
                echo -e "\n${YELLOW}客户端日志 (最新50行):${NC}\n"
                tail -n 50 "$LOG_DIR/client.log"
            else
                print_message "error" "客户端日志文件不存在"
            fi
            ;;
        3)
            local service
            echo "a) 服务端系统日志"
            echo "b) 客户端系统日志"
            read -p "请选择: " service
            
            if [ "$service" = "a" ]; then
                if [ -f "/etc/systemd/system/$SERVER_SERVICE.service" ]; then
                    echo -e "\n${YELLOW}服务端系统日志:${NC}\n"
                    journalctl -u "$SERVER_SERVICE" --no-pager -n 50
                else
                    print_message "error" "服务端未安装"
                fi
            elif [ "$service" = "b" ]; then
                if [ -f "/etc/systemd/system/$CLIENT_SERVICE.service" ]; then
                    echo -e "\n${YELLOW}客户端系统日志:${NC}\n"
                    journalctl -u "$CLIENT_SERVICE" --no-pager -n 50
                else
                    print_message "error" "客户端未安装"
                fi
            else
                print_message "error" "无效的选择"
            fi
            ;;
        0)
            return
            ;;
        *)
            print_message "error" "无效的选择"
            ;;
    esac
    
    read -p "按回车键继续..."
}

# Function to modify configurations
modify_config() {
    print_header
    echo -e "${CYAN}修改配置...${NC}\n"
    
    local selected_config
    echo "1) 修改服务端配置"
    echo "2) 修改客户端配置"
    echo "0) 返回"
    echo ""
    read -p "请选择: " selected_config
    
    case $selected_config in
        1)
            if [ -f "$SERVER_CONFIG" ]; then
                # Check for installed editors
                local editor
                if command_exists nano; then
                    editor="nano"
                elif command_exists vi; then
                    editor="vi"
                else
                    print_message "error" "未找到可用的文本编辑器 (nano或vi)"
                    read -p "按回车键继续..."
                    return
                fi
                
                # Open the config file with the editor
                $editor "$SERVER_CONFIG"
                
                # Ask if user wants to restart service
                read -p "是否重启服务端以应用更改？(y/n): " restart
                if [ "$restart" = "y" ]; then
                    systemctl restart "$SERVER_SERVICE"
                    print_message "success" "服务端已重启，配置已应用"
                fi
            else
                print_message "error" "服务端配置文件不存在"
            fi
            ;;
        2)
            if [ -f "$CLIENT_CONFIG" ]; then
                # Check for installed editors
                local editor
                if command_exists nano; then
                    editor="nano"
                elif command_exists vi; then
                    editor="vi"
                else
                    print_message "error" "未找到可用的文本编辑器 (nano或vi)"
                    read -p "按回车键继续..."
                    return
                fi
                
                # Open the config file with the editor
                $editor "$CLIENT_CONFIG"
                
                # Ask if user wants to restart service
                read -p "是否重启客户端以应用更改？(y/n): " restart
                if [ "$restart" = "y" ]; then
                    systemctl restart "$CLIENT_SERVICE"
                    print_message "success" "客户端已重启，配置已应用"
                fi
            else
                print_message "error" "客户端配置文件不存在"
            fi
            ;;
        0)
            return
            ;;
        *)
            print_message "error" "无效的选择"
            ;;
    esac
    
    read -p "按回车键继续..."
}

# Function to uninstall
uninstall() {
    print_header
    echo -e "${RED}卸载服务...${NC}\n"
    
    local selected_service
    echo "1) 卸载服务端"
    echo "2) 卸载客户端"
    echo "3) 卸载所有服务"
    echo "0) 返回"
    echo ""
    read -p "请选择: " selected_service
    
    case $selected_service in
        1)
            print_message "warning" "您确定要卸载服务端吗？所有数据将被删除。"
            read -p "输入 'yes' 确认卸载: " confirm
            if [ "$confirm" = "yes" ]; then
                if [ -f "/etc/systemd/system/$SERVER_SERVICE.service" ]; then
                    systemctl stop "$SERVER_SERVICE"
                    systemctl disable "$SERVER_SERVICE"
                    rm -f "/etc/systemd/system/$SERVER_SERVICE.service"
                    systemctl daemon-reload
                fi
                
                rm -rf "$SERVER_INSTALL_DIR"
                rm -rf "$SERVER_CONFIG_DIR"
                
                print_message "success" "服务端已卸载"
            else
                print_message "info" "卸载取消"
            fi
            ;;
        2)
            print_message "warning" "您确定要卸载客户端吗？"
            read -p "输入 'yes' 确认卸载: " confirm
            if [ "$confirm" = "yes" ]; then
                if [ -f "/etc/systemd/system/$CLIENT_SERVICE.service" ]; then
                    systemctl stop "$CLIENT_SERVICE"
                    systemctl disable "$CLIENT_SERVICE"
                    rm -f "/etc/systemd/system/$CLIENT_SERVICE.service"
                    systemctl daemon-reload
                fi
                
                rm -rf "$CLIENT_INSTALL_DIR"
                rm -rf "$CLIENT_CONFIG_DIR"
                
                print_message "success" "客户端已卸载"
            else
                print_message "info" "卸载取消"
            fi
            ;;
        3)
            print_message "warning" "您确定要卸载所有服务吗？所有数据将被删除。"
            read -p "输入 'yes' 确认卸载: " confirm
            if [ "$confirm" = "yes" ]; then
                # Uninstall server
                if [ -f "/etc/systemd/system/$SERVER_SERVICE.service" ]; then
                    systemctl stop "$SERVER_SERVICE"
                    systemctl disable "$SERVER_SERVICE"
                    rm -f "/etc/systemd/system/$SERVER_SERVICE.service"
                fi
                
                # Uninstall client
                if [ -f "/etc/systemd/system/$CLIENT_SERVICE.service" ]; then
                    systemctl stop "$CLIENT_SERVICE"
                    systemctl disable "$CLIENT_SERVICE"
                    rm -f "/etc/systemd/system/$CLIENT_SERVICE.service"
                fi
                
                systemctl daemon-reload
                
                rm -rf "$SERVER_INSTALL_DIR"
                rm -rf "$CLIENT_INSTALL_DIR"
                rm -rf "$SERVER_CONFIG_DIR"
                rm -rf "$CLIENT_CONFIG_DIR"
                
                read -p "是否删除日志文件？(y/n): " delete_logs
                if [ "$delete_logs" = "y" ]; then
                    rm -rf "$LOG_DIR"
                fi
                
                print_message "success" "所有服务已卸载"
            else
                print_message "info" "卸载取消"
            fi
            ;;
        0)
            return
            ;;
        *)
            print_message "error" "无效的选择"
            ;;
    esac
    
    read -p "按回车键继续..."
}

# Function to test client connection
test_client() {
    print_header
    echo -e "${CYAN}测试客户端连接...${NC}\n"
    
    if [ ! -d "$CLIENT_INSTALL_DIR" ]; then
        print_message "error" "客户端未安装"
        read -p "按回车键继续..."
        return
    fi
    
    # Run client with test flag
    print_message "info" "正在测试客户端连接..."
    cd "$CLIENT_INSTALL_DIR"
    source venv/bin/activate
    python client.py --test
    
    read -p "按回车键继续..."
}

# Clean up function
cleanup() {
    print_message "info" "清理临时文件..."
    rm -rf "$TEMP_DIR"
}

# Main menu function
show_main_menu() {
    while true; do
        print_header
        echo "请选择操作:"
        echo ""
        echo -e "${GREEN}安装${NC}"
        echo "1) 安装服务端"
        echo "2) 安装客户端"
        echo ""
        echo -e "${BLUE}服务管理${NC}"
        echo "3) 启动服务"
        echo "4) 停止服务"
        echo "5) 重启服务"
        echo "6) 查看服务状态"
        echo "7) 查看日志"
        echo "8) 修改配置"
        echo ""
        echo -e "${YELLOW}工具${NC}"
        echo "9) 测试客户端连接"
        echo ""
        echo -e "${RED}卸载${NC}"
        echo "10) 卸载服务"
        echo ""
        echo "0) 退出"
        echo ""
        read -p "请输入选项: " choice
        
        case $choice in
            1) install_server ;;
            2) install_client ;;
            3) start_services ;;
            4) stop_services ;;
            5) restart_services ;;
            6) view_status ;;
            7) view_logs ;;
            8) modify_config ;;
            9) test_client ;;
            10) uninstall ;;
            0) 
                cleanup
                print_message "info" "感谢使用系统监控管理工具！"
                exit 0 
                ;;
            *) 
                print_message "error" "无效的选项，请重新选择" 
                sleep 1
                ;;
        esac
    done
}

# Register cleanup on script exit
trap cleanup EXIT

# Check if running as root
check_root

# Start the main menu
show_main_menu
