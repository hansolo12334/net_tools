import pydivert
import psutil
import sqlite3
from datetime import datetime,timedelta
import threading
import time
import sys
import ctypes
from collections import defaultdict
import socket

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

# 获取进程信息（通过本地端口，添加缓存）
process_cache = {}
def get_process_by_port(local_port):
    if local_port in process_cache:
        return process_cache[local_port]
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr.port == local_port:
                try:
                    proc = psutil.Process(conn.pid)
                    process_name = proc.name()
                    process_cache[local_port] = process_name
                    return process_name
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_cache[local_port] = "unknown"
                    return "unknown"
    except psutil.AccessDenied:
        print("Warning: Access denied to network connections. Run script with administrator privileges.")
    process_cache[local_port] = "unknown"
    return "unknown"

# 保存流量数据到数据库
def save_to_db(process_name, upload_bytes, download_bytes, timestamp, granularity):
    try:
        conn = sqlite3.connect('traffic_monitor.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO traffic (timestamp, process_name, upload_bytes, download_bytes, time_granularity)
            VALUES (?, ?, ?, ?, ?)
        ''', (timestamp, process_name, upload_bytes, download_bytes, granularity))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()

# 定时打印统计结果
def print_stats():
    while True:
        print("\n=== 每秒流量统计 ===")
        for process, data in traffic_data.items():
            for second, bytes_total in data['per_second'].items():
                print(f"{process} at {second}: {bytes_total / 1024:.2f} KB")
        # 清理旧数据（保留最近 5 分钟）
        now = datetime.now()
        cutoff = (now - timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S')
        for process in traffic_data:
            traffic_data[process]['per_second'] = {
                k: v for k, v in traffic_data[process]['per_second'].items() if k > cutoff
            }
        time.sleep(60)  # 每分钟打印一次

# 数据包处理
def process_packet(packet:pydivert.packet.Packet, local_ips:list):
    packet_size = len(packet.payload)
    src_ip, dst_ip = packet.src_addr, packet.dst_addr
    protocol = 'tcp' if packet.is_tcp_packet else 'udp' if packet.is_udp_packet else 'other'

    # 获取当前时间
    now = datetime.now()
    second_key = now.strftime('%Y-%m-%d %H:%M:%S')
    minute_key = now.strftime('%Y-%m-%d %H:%M')
    hour_key = now.strftime('%Y-%m-%d %H')
    day_key = now.strftime('%Y-%m-%d')

    process_name = "unknown"
    if protocol in ('tcp', 'udp'):
        local_port = None
        if src_ip in local_ips:
            # 上传流量（本地 -> 远程）
            local_port = packet.src_port
            process_name = get_process_by_port(local_port)
            traffic_data[process_name]['per_second'][second_key] += packet_size
            traffic_data[process_name]['per_minute'][minute_key] += packet_size
            traffic_data[process_name]['per_hour'][hour_key] += packet_size
            traffic_data[process_name]['per_day'][day_key] += packet_size
            save_to_db(process_name, packet_size, 0, second_key, 'second')
        elif dst_ip in local_ips:
            # 下载流量（远程 -> 本地）
            local_port = packet.dst_port
            process_name = get_process_by_port(local_port)
            traffic_data[process_name]['per_second'][second_key] += packet_size
            traffic_data[process_name]['per_minute'][minute_key] += packet_size
            traffic_data[process_name]['per_hour'][hour_key] += packet_size
            traffic_data[process_name]['per_day'][day_key] += packet_size
            save_to_db(process_name, 0, packet_size, second_key, 'second')

# 捕获数据包
def capture_traffic():
    try:
        # 获取本地 IP
        local_ips = []
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    local_ips.append(addr.address)
        if not local_ips:
            raise Exception("No local IP addresses found")

        print(f"Local IPs: {local_ips}")
        # 使用 pydivert 捕获 TCP/UDP 数据包
        with pydivert.WinDivert("tcp or udp") as w:
            print("Starting packet capture...")
            for packet in w:
                process_packet(packet, local_ips)
                w.send(packet)  # 必须发送数据包，避免中断网络
    except Exception as e:
        print(f"Error capturing packets: {e}")
        sys.exit(1)

# 主程序
if __name__ == "__main__":
    # 检查管理员权限
    # if sys.platform == "win32" and not ctypes.windll.shell32.IsUserAnAdmin():
    #     print("Error: This script requires administrator privileges for packet capture.")
    #     sys.exit(1)

    # 初始化数据库
    init_db()

    # 启动统计线程
    threading.Thread(target=print_stats, daemon=True).start()

    # 启动数据包捕获
    capture_traffic()
