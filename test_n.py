
import scapy.all as scapy
import psutil
import sqlite3
import socket
from datetime import datetime, timedelta
import threading
import time
import sys
import ctypes
from collections import defaultdict
import os

# 流量统计数据结构
traffic_data = defaultdict(lambda: {
    'per_second': defaultdict(int),
    'per_minute': defaultdict(int),
    'per_hour': defaultdict(int),
    'per_day': defaultdict(int)
})

# 线程控制
stop_event = threading.Event()

# SQLite 数据库初始化
def init_db():
    conn = sqlite3.connect('traffic_monitor.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS traffic (
            timestamp TEXT,
            process_name TEXT,
            domain TEXT,
            upload_bytes INTEGER,
            download_bytes INTEGER,
            time_granularity TEXT,
            ip_version TEXT
        )
    ''')
    conn.commit()
    conn.close()

# 获取进程信息（通过本地端口，添加缓存）
process_cache = {}
process_cache_time = {}
process_cache = {}
def get_process_by_port(local_port, ip_version='IPv4'):
    now = time.time()
    cache_key = (local_port, ip_version)
    if cache_key in process_cache and now - process_cache_time.get(cache_key, 0) < 60:
        return process_cache[cache_key]
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr.port == local_port:
                if (ip_version == 'IPv4' and conn.family == socket.AF_INET) or (ip_version == 'IPv6' and conn.family == socket.AF_INET6):
                    try:
                        proc = psutil.Process(conn.pid)
                        process_name = proc.name()
                        process_cache[cache_key] = process_name
                        process_cache_time[cache_key] = now
                        return process_name
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        process_cache[cache_key] = "unknown"
                        process_cache_time[cache_key] = now
                        return "unknown"
    except psutil.AccessDenied:
        print("Warning: Access denied to network connections. Run script with administrator privileges.")
    process_cache[cache_key] = "unknown"
    process_cache_time[cache_key] = now
    return "unknown"

# 保存流量数据到数据库
def save_to_db(process_name, upload_bytes, download_bytes, timestamp, granularity, domain=None, ip_version='IPv4'):
    try:
        conn = sqlite3.connect('traffic_monitor.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO traffic (timestamp, process_name, domain, upload_bytes, download_bytes, time_granularity, ip_version)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, process_name, domain, upload_bytes, download_bytes, granularity, ip_version))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()

# 定时打印统计结果
def print_stats():
    while not stop_event.is_set():
        try:
            print("\n=== 每秒流量统计 ===")
            print(stop_event.is_set())
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
            time.sleep(60)
        except Exception as e:
            print(f"Error in print_stats: {e}")
            break

# 数据包处理
# 数据包处理
def process_packet(packet, local_ips, local_ipv6s):
    try:
        process_name = "unknown"
        packet_size = len(packet)
        
        now = datetime.now()
        second_key = now.strftime('%Y-%m-%d %H:%M:%S')
        minute_key = now.strftime('%Y-%m-%d %H:%M')
        hour_key = now.strftime('%Y-%m-%d %H')
        day_key = now.strftime('%Y-%m-%d')
        domain = None

        # print(f"{second_key} Processing packet of size {packet_size/(1024*1024)} Mb")
        # 处理 DNS（识别 bilibili.com）
        # if packet.haslayer(scapy.DNS) and packet[scapy.DNS].qr == 0:
        #     domain = packet[scapy.DNSQR].qname.decode().rstrip('.')
        #     if 'bilibili.com' in domain:
        #         print(f"DNS Request: {domain}")

        # 处理 TLS SNI
        # if packet.haslayer(scapy.TLS) and packet[scapy.TLS].type == 22:
        #     sni = packet[scapy.TLS].getfieldval('servernames')
        #     if sni and 'bilibili.com' in sni[0].servername.decode():
        #         domain = sni[0].servername.decode()
        #         print(f"TLS SNI: {domain}")

        # IPv4 数据包
        if packet.haslayer(scapy.IP):
            ip_layer = packet[scapy.IP]
            src_ip, dst_ip = ip_layer.src, ip_layer.dst
            if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
                local_port = None
                if src_ip in local_ips:
                    local_port = packet[scapy.TCP].sport if packet.haslayer(scapy.TCP) else packet[scapy.UDP].sport
                    process_name = get_process_by_port(local_port, 'IPv4')
                    traffic_data[process_name]['per_second'][second_key] += packet_size
                    traffic_data[process_name]['per_minute'][minute_key] += packet_size
                    traffic_data[process_name]['per_hour'][hour_key] += packet_size
                    traffic_data[process_name]['per_day'][day_key] += packet_size
                    # print(f"IPv4 Packet: {src_ip} -> {dst_ip}, Size: {packet_size} bytes , process_name: {process_name}")
                    # save_to_db(process_name, packet_size, 0, second_key, 'second', domain, 'IPv4')
                elif dst_ip in local_ips:
                    local_port = packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else packet[scapy.UDP].dport
                    process_name = get_process_by_port(local_port, 'IPv4')
                    traffic_data[process_name]['per_second'][second_key] += packet_size
                    traffic_data[process_name]['per_minute'][minute_key] += packet_size
                    traffic_data[process_name]['per_hour'][hour_key] += packet_size
                    traffic_data[process_name]['per_day'][day_key] += packet_size
                    # print(f"IPv4 Packet: {src_ip} -> {dst_ip}, Size: {packet_size} bytes , process_name: {process_name}")
                    # save_to_db(process_name, 0, packet_size, second_key, 'second', domain, 'IPv4')

        # IPv6 数据包
        elif packet.haslayer(scapy.IPv6):
            ip_layer = packet[scapy.IPv6]
            src_ip, dst_ip = ip_layer.src, ip_layer.dst
            if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
                local_port = None
                if src_ip in local_ipv6s:
                    local_port = packet[scapy.TCP].sport if packet.haslayer(scapy.TCP) else packet[scapy.UDP].sport
                    process_name = get_process_by_port(local_port, 'IPv6')
                    traffic_data[process_name]['per_second'][second_key] += packet_size
                    traffic_data[process_name]['per_minute'][minute_key] += packet_size
                    traffic_data[process_name]['per_hour'][hour_key] += packet_size
                    traffic_data[process_name]['per_day'][day_key] += packet_size
                    # print(f"IPv6 Packet: {src_ip} -> {dst_ip}, Size: {packet_size} bytes , process_name: {process_name}")
                    # save_to_db(process_name, packet_size, 0, second_key, 'second', domain, 'IPv6')
                elif dst_ip in local_ipv6s:
                    local_port = packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else packet[scapy.UDP].dport
                    process_name = get_process_by_port(local_port, 'IPv6')
                    traffic_data[process_name]['per_second'][second_key] += packet_size
                    traffic_data[process_name]['per_minute'][minute_key] += packet_size
                    traffic_data[process_name]['per_hour'][hour_key] += packet_size
                    traffic_data[process_name]['per_day'][day_key] += packet_size
                    # print(f"IPv6 Packet: {src_ip} -> {dst_ip}, Size: {packet_size} bytes , process_name: {process_name}")
                    # save_to_db(process_name, 0, packet_size, second_key, 'second', domain, 'IPv6')

    except Exception as e:
        print(f"Error processing packet: {e}")

# 获取活跃网络接口
# def get_active_interface():
#     scapy_ifaces = scapy.get_if_list()
#     psutil_ifaces = psutil.net_if_addrs()
#     for scapy_iface in scapy_ifaces:
#         if 'Loopback' in scapy_iface:
#             continue
#         for psutil_iface, addrs in psutil_ifaces.items():
#             for addr in addrs:
#                 if addr.family == socket.AF_INET and addr.address != '127.0.0.1' and addr.address=='192.168.50.28':
#                     try:
#                         # 测试接口是否有流量
#                         scapy.conf.iface = scapy_iface
#                         pkt = scapy.sniff(iface=scapy_iface, count=1, timeout=0.5)  # 增加 timeout
#                         if pkt:
#                             return scapy_iface, [addr.address]
#                     except Exception as e:
#                         print(f"Interface {scapy_iface} test failed: {e}")
#                         continue
#     raise Exception("No valid network interface with traffic found")


# 获取活跃网络接口（简化：直接匹配以太网 3）
# 获取活跃网络接口（匹配以太网 3）
def get_active_interface():
    target_psutil_iface = '以太网 3'
    scapy_ifaces = scapy.get_if_list()
    psutil_ifaces = psutil.net_if_addrs()
    
    if target_psutil_iface not in psutil_ifaces:
        raise Exception(f"Interface {target_psutil_iface} not found in psutil interfaces")
    
    local_ips = []
    local_ipv6s = []
    for addr in psutil_ifaces[target_psutil_iface]:
        if addr.family == socket.AF_INET and addr.address != '127.0.0.1':
            local_ips.append(addr.address)
        elif addr.family == socket.AF_INET6 and not addr.address.startswith('fe80::'):
            local_ipv6s.append(addr.address)
    
    if not (local_ips or local_ipv6s):
        raise Exception(f"No valid IP addresses found for {target_psutil_iface}")
    
    for scapy_iface in scapy_ifaces:
        if 'Loopback' in scapy_iface:
            continue
        try:
            scapy.conf.iface = scapy_iface
            iface_ip = scapy.get_if_addr(scapy_iface)
            if iface_ip in local_ips or iface_ip in local_ipv6s:
                return scapy_iface, local_ips, local_ipv6s
        except:
            continue
    
    raise Exception("No matching Scapy interface found for 以太网 3")

# 捕获数据包
def capture_traffic():
    try:
        iface, local_ips, local_ipv6s = get_active_interface()
        print(f"Capturing on interface: {iface}")
        print(f"IPv4 IPs: {local_ips}")
        print(f"IPv6 IPs: {local_ipv6s}")
        scapy.sniff(iface=iface, prn=lambda pkt: process_packet(pkt, local_ips, local_ipv6s), store=False, filter="ip or ip6", timeout=30, stop_filter=lambda x: stop_event.is_set())
    except Exception as e:
        print(f"Error capturing packets: {e}")
        stop_event.set()
        sys.exit(1)

# 主程序
if __name__ == "__main__":
    # 设置 DLL 路径
    dll_path = os.path.dirname(os.path.abspath(__file__))  # Python 程序目录
    os.add_dll_directory(dll_path)  # 添加到 DLL 搜索路径
    # 检查管理员权限
    # if sys.platform == "win32" and not ctypes.windll.shell32.IsUserAnAdmin():
    #     print("Error: This script requires administrator privileges for packet capture.")
    #     sys.exit(1)

    # 检查 Npcap
    try:
        # 尝试加载 wpcap.dll
        ctypes.WinDLL(os.path.join(dll_path, "Packet.dll"))
        ctypes.WinDLL(os.path.join(dll_path, "wpcap.dll"))
        interfaces = scapy.get_if_list()
        if not interfaces:
            raise Exception("No network interfaces found")
        print("Available interfaces:", interfaces)
    except Exception as e:
        print(f"Error: Failed to load wpcap.dll or get interfaces: {e}")
        print("Ensure wpcap.dll and Packet.dll are in C:\\Windows\\System32 or PATH.")
        sys.exit(1)

    # 初始化数据库
    init_db()

    # 启动统计线程
    threading.Thread(target=print_stats, daemon=True).start()

    # 启动数据包捕获
    try:
        print("Starting packet capture...")
        capture_traffic()
    except KeyboardInterrupt:
        print("Stopping packet capture...")
        stop_event.set()
        time.sleep(1)  # 等待线程退出
        scapy.sniff_stop()  # 显式停止 sniff
        sys.exit(0)
    except Exception as e:
        print(f"Unexpected error: {e}")
        stop_event.set()
        scapy.sniff_stop()  # 确保停止 sniff
        sys.exit(1)
