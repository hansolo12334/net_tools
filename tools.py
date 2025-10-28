from mitmproxy import http, ctx
import psutil
import time
from collections import defaultdict
import threading
import sqlite3
from datetime import datetime

import subprocess
import atexit
import signal
import sys
import os
import ctypes

# 注册端口转发规则

# 全局标志，跟踪清理是否完成
CLEANUP_DONE = False


# 检查端口转发规则是否存在
def check_port_forwarding(port, listenaddress='127.0.0.1'):
    try:
        result = subprocess.run(['netsh', 'interface', 'portproxy', 'show', 'v4tov4'], capture_output=True, text=True)
        return f"listenport={port} listenaddress={listenaddress}" in result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error checking port forwarding: {e}")
        return False
    
# 配置端口转发
def setup_port_forwarding():
    if sys.platform != "win32":
        print("Error: Port forwarding via netsh is only supported on Windows.")
        return False

    ports = [80, 443]
    for port in ports:
        if check_port_forwarding(port):
            print(f"Port forwarding for port {port} already configured.")
            continue
        try:
            subprocess.run([
                'netsh', 'interface', 'portproxy', 'add', 'v4tov4',
                f'listenport={port}', f'listenaddress=127.0.0.1',
                'connectport=8080', 'connectaddress=127.0.0.1'
            ], check=True)
            print(f"Port forwarding configured: {port} -> 127.0.0.1:8080")
        except subprocess.CalledProcessError as e:
            print(f"Error setting up port forwarding for port {port}: {e}")
            return False
    return True

# 清理端口转发
def cleanup_port_forwarding():
    global CLEANUP_DONE
    
    if sys.platform != "win32" or CLEANUP_DONE:
        return

    ports = [80, 443]
    for port in ports:
        try:
            # 直接尝试删除规则，忽略不存在的错误
            # subprocess.run(
            #     [
            #         'netsh', 'interface', 'portproxy', 'delete', 'v4tov4',
            #         f'listenport={port}', f'listenaddress=127.0.0.1'
            #     ],
            #     capture_output=True,
            #     text=True,
            #     check=False  # 不抛出异常
            # )
            subprocess.run([
                'netsh', 'interface', 'portproxy', 'delete', 'v4tov4',
                f'listenport={port}', f'listenaddress=127.0.0.1'
            ], check=True)
            print(f"Port forwarding rule removed for port {port}.")
        except subprocess.CalledProcessError as e:
            print(f"Error cleaning up port forwarding for port {port}: {e}. Continuing cleanup.")
        
    CLEANUP_DONE = True  # 标记清理完成
    
# 注册清理函数
def register_cleanup():
    atexit.register(cleanup_port_forwarding)
    def signal_handler(sig, frame):
        cleanup_port_forwarding()
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)  # 捕获 Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler)  # 捕获终止信号
    


#主程序


# 流量统计数据结构
traffic_data = defaultdict(lambda: {
    'per_second': defaultdict(int),
    'per_minute': defaultdict(int),
    'per_hour': defaultdict(int),
    'per_day': defaultdict(int)
})

# SQLite 数据库初始化
def init_db():
    conn = sqlite3.connect('traffic_monitor.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS traffic (
            timestamp TEXT,
            process_name TEXT,
            upload_bytes INTEGER,
            download_bytes INTEGER,
            time_granularity TEXT
        )
    ''')
    conn.commit()
    conn.close()

# 获取客户端进程信息
def get_process_by_port(client_port):
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr.port == client_port:
                try:
                    proc = psutil.Process(conn.pid)
                    return proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    return "unknown"
    except psutil.AccessDenied:
        print("Warning: Access denied to network connections. Run script with administrator privileges.")
    return "unknown"


# mitmproxy 的请求处理
def request(flow: http.HTTPFlow):
    client_port = flow.client_conn.address[1]  # 客户端端口
    process_name = get_process_by_port(client_port)
    upload_bytes = len(flow.request.content) if flow.request.content else 0

    # 获取当前时间
    now = datetime.now()
    second_key = now.strftime('%Y-%m-%d %H:%M:%S')
    minute_key = now.strftime('%Y-%m-%d %H:%M')
    hour_key = now.strftime('%Y-%m-%d %H')
    day_key = now.strftime('%Y-%m-%d')

    # 更新流量统计
    traffic_data[process_name]['per_second'][second_key] += upload_bytes
    traffic_data[process_name]['per_minute'][minute_key] += upload_bytes
    traffic_data[process_name]['per_hour'][hour_key] += upload_bytes
    traffic_data[process_name]['per_day'][day_key] += upload_bytes

    # 记录到数据库
    save_to_db(process_name, upload_bytes, 0, second_key, 'second')
    
# mitmproxy 的响应处理
def response(flow: http.HTTPFlow):
    client_port = flow.client_conn.address[1]
    process_name = get_process_by_port(client_port)
    download_bytes = len(flow.response.content) if flow.response.content else 0

    now = datetime.now()
    second_key = now.strftime('%Y-%m-%d %H:%M:%S')
    minute_key = now.strftime('%Y-%m-%d %H:%M')
    hour_key = now.strftime('%Y-%m-%d %H')
    day_key = now.strftime('%Y-%m-%d')

    traffic_data[process_name]['per_second'][second_key] += download_bytes
    traffic_data[process_name]['per_minute'][minute_key] += download_bytes
    traffic_data[process_name]['per_hour'][hour_key] += download_bytes
    traffic_data[process_name]['per_day'][day_key] += download_bytes
    
# 保存到数据库
def save_to_db(process_name, upload_bytes, download_bytes, timestamp, granularity):
    conn = sqlite3.connect('traffic_monitor.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO traffic (timestamp, process_name, upload_bytes, download_bytes, time_granularity)
        VALUES (?, ?, ?, ?, ?)
    ''', (timestamp, process_name, upload_bytes, download_bytes, granularity))
    conn.commit()
    conn.close()

# 定时打印统计结果
def print_stats():
    while True:
        print("\n=== 每秒流量统计 ===")
        for process, data in traffic_data.items():
            for second, bytes_total in data['per_second'].items():
                print(f"{process} at {second}: {bytes_total / 1024:.2f} KB")
        time.sleep(60)  # 每分钟打印一次

# 启动统计线程
def start_stats_printer():
    threading.Thread(target=print_stats, daemon=True).start()
    
    
# mitmproxy 配置
if __name__ == "__main__":
    
    # 检查管理员权限
    if sys.platform == "win32" and not ctypes.windll.shell32.IsUserAnAdmin():
        print("Error: This script requires administrator privileges to configure port forwarding.")
        sys.exit(1)
        
    
        
    
    
    
    init_db()
    start_stats_printer()
    
    # if not setup_port_forwarding():
    #     print("Failed to set up port forwarding. Exiting.")
    #     sys.exit(1)
    
    # # 注册清理函数
    # register_cleanup()

    from mitmproxy.tools.main import mitmdump
    mitmdump(['-s', __file__, '--mode', 'wireguard', '--listen-port', str(8080)])
    # mitmdump(['-s', __file__, '--listen-port', '8080'])