# import argparse
# import queue
# import threading
# import time
# from scapy.all import sniff, get_if_list, get_if_addr, get_if_hwaddr
# from scapy.layers.l2 import Ether

# def get_args():
#     parser = argparse.ArgumentParser(description="Network traffic monitor")
#     parser.add_argument("-i", "--interface", default="eth0", help="Network interface name (default: eth0)")
#     return parser.parse_args()

# def find_device_ipv4(interface):
#     """获取指定网卡的 IPv4 地址"""
#     try:
#         return get_if_addr(interface)
#     except Exception as e:
#         raise Exception(f"无法获取网卡 {interface} 的 IPv4 地址: {e}")

# def find_mac_addr_by_ip(ip, interface):
#     """根据 IPv4 地址获取网卡的 MAC 地址"""
#     try:
#         return get_if_hwaddr(interface)
#     except Exception as e:
#         raise Exception(f"未找到网卡 {interface} 的 MAC 地址: {e}")

# def monitor(down_queue, up_queue):
#     """监控线程，每秒统计并打印网速和累计流量"""
#     down_total = 0  # 累计下行字节数
#     up_total = 0    # 累计上行字节数
#     down_size = 0   # 本秒下行字节数
#     up_size = 0     # 本秒上行字节数

#     while True:
#         start_time = time.time()
#         # 在 1 秒内收集队列中的数据
#         while time.time() - start_time < 1.0:
#             try:
#                 # 非阻塞获取下行数据
#                 while True:
#                     size = down_queue.get_nowait()
#                     down_size += size
#                     down_total += size
#                     down_queue.task_done()
#             except queue.Empty:
#                 pass
#             try:
#                 # 非阻塞获取上行数据
#                 while True:
#                     size = up_queue.get_nowait()
#                     up_size += size
#                     up_total += size
#                     up_queue.task_done()
#             except queue.Empty:
#                 pass
#             time.sleep(0.01)  # 避免 CPU 占用过高

#         # 计算网速（KB/s）和累计流量（MB）
#         down_speed = down_size / (1024.0*1024.0)
#         up_speed = up_size / (1024.0*1024.0)
#         down_total_mb = down_total / 1024.0 / 1024.0
#         up_total_mb = up_total / 1024.0 / 1024.0

#         # 打印网速和累计流量
#         print(f"\r下行: {down_speed:.2f} MB/s \t 上行: {up_speed:.2f} MB/s \t "f"累计下行: {down_total_mb:.2f} MB \t 累计上行: {up_total_mb:.2f} MB", end="")

#         # 重置每秒计数器
#         down_size = 0
#         up_size = 0

# def main():
#     # args = get_args()
#     # interface = args.interface
#     interface=r'\Device\NPF_{534450E4-320B-4A4B-8FB0-E699DFE7AD2B}'

#     # 验证网卡存在
#     if interface not in get_if_list():
#         raise Exception(f"网卡 {interface} 不存在")

#     # 获取网卡的 IPv4 和 MAC 地址
#     ipv4 = find_device_ipv4(interface)
#     mac_addr = find_mac_addr_by_ip(ipv4, interface)
#     print(f"网卡 IPv4 地址: {ipv4}")
#     print(f"网卡 MAC 地址: {mac_addr}")

#     # 创建上下行数据队列
#     down_queue = queue.Queue(maxsize=10000)
#     up_queue = queue.Queue(maxsize=10000)

#     # 启动监控线程
#     monitor_thread = threading.Thread(target=monitor, args=(down_queue, up_queue), daemon=True)
#     monitor_thread.start()

#     def packet_handler(packet):
#         """处理捕获的数据包"""
#         if Ether in packet:
#             eth = packet[Ether]
#             # 如果目标 MAC 是本机 MAC，则为下行；否则为上行
#             if eth.dst == mac_addr:
#                 down_queue.put(len(packet))
#             else:
#                 up_queue.put(len(packet))

#     # 开始捕获数据包
#     try:
#         sniff(iface=interface, prn=packet_handler, store=False,promisc=True)
#     except Exception as e:
#         print(f"\n捕获数据包时出错: {e}")

# if __name__ == "__main__":
#     try:
#         main()
#     except KeyboardInterrupt:
#         print("\n停止监控")
#     except Exception as e:
#         print(f"错误: {e}")


import argparse
import queue
import threading
import time
import psutil
import pcap
import dpkt
import netifaces

def get_args():
    parser = argparse.ArgumentParser(description="网络流量监控器，模仿 AppNetworkCounter")
    parser.add_argument("-i", "--interface", default="eth0", help="网络接口名称（默认: eth0）")
    return parser.parse_args()

def find_device_ipv4(interface):
    """获取指定网卡的 IPv4 地址"""
    try:
        return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
    except Exception as e:
        raise Exception(f"无法获取网卡 {interface} 的 IPv4 地址: {e}")

def find_mac_addr(interface):
    """获取指定网卡的 MAC 地址"""
    try:
        return netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr'].lower()
    except Exception as e:
        raise Exception(f"未找到网卡 {interface} 的 MAC 地址: {e}")

def monitor(down_queue, up_queue, packet_queue):
    """监控线程，每秒统计并打印网速、累计流量和数据包计数"""
    down_total = 0  # 累计下行字节数
    up_total = 0    # 累计上行字节数
    down_size = 0   # 本秒下行字节数
    up_size = 0     # 本秒上行字节数
    packet_count = 0  # 本秒数据包计数
    dropped_packets = 0  # 本秒丢包计数

    while True:
        start_time = time.time()
        while time.time() - start_time < 1.0:
            try:
                while True:
                    size = down_queue.get_nowait()
                    down_size += size
                    down_total += size
                    down_queue.task_done()
            except queue.Empty:
                pass
            try:
                while True:
                    size = up_queue.get_nowait()
                    up_size += size
                    up_total += size
                    up_queue.task_done()
            except queue.Empty:
                pass
            try:
                while True:
                    count_type, count = packet_queue.get_nowait()
                    if count_type == "packet":
                        packet_count += count
                    elif count_type == "dropped":
                        dropped_packets += count
                    packet_queue.task_done()
            except queue.Empty:
                pass
            time.sleep(0.0001)  # 最小化延迟

        # 计算网速（MB/s）和累计流量（MB）
        down_speed = down_size / 1024.0 / 1024.0
        up_speed = up_size / 1024.0 / 1024.0
        down_total_mb = down_total / 1024.0 / 1024.0
        up_total_mb = up_total / 1024.0 / 1024.0

        # 打印网速、累计流量和数据包统计
        print(f"\r下行: {down_speed:.2f} MB/s \t 上行: {up_speed:.2f} MB/s \t " f"累计下行: {down_total_mb:.2f} MB \t 累计上行: {up_total_mb:.2f} MB \t "  f"数据包: {packet_count} \t 丢包: {dropped_packets}", end="", flush=True)

        # 重置每秒计数器
        down_size = 0
        up_size = 0
        packet_count = 0
        dropped_packets = 0

        # 检查系统性能
        cpu_usage = psutil.cpu_percent(interval=0.1)
        mem_usage = psutil.virtual_memory().percent
        if cpu_usage > 80 or mem_usage > 80:
            print(f"\n警告: 高 CPU 使用率 ({cpu_usage:.1f}%) 或内存使用率 ({mem_usage:.1f}%)，可能导致丢包", flush=True)

def main():
    args = get_args()
    interface = args.interface

    # 获取网卡的 IPv4 和 MAC 地址
    ipv4 = find_device_ipv4(interface)
    mac_addr = find_mac_addr(interface)
    print(f"网卡 IPv4 地址: {ipv4}")
    print(f"网卡 MAC 地址: {mac_addr}")

    # 创建队列
    down_queue = queue.Queue(maxsize=20000)
    up_queue = queue.Queue(maxsize=20000)
    packet_queue = queue.Queue(maxsize=20000)  # 用于数据包和丢包计数

    # 启动监控线程
    monitor_thread = threading.Thread(target=monitor, args=(down_queue, up_queue, packet_queue), daemon=True)
    monitor_thread.start()

    # 初始化 pcap
    pc = pcap.pcap(name=interface, snaplen=65535, promisc=True, timeout_ms=50)
    pc.setfilter('tcp or udp')  # 只捕获 TCP 和 UDP 数据包

    def packet_handler(ts, pkt):
        """处理捕获的数据包"""
        try:
            eth = dpkt.ethernet.Ethernet(pkt)
            # 仅处理 TCP 或 UDP 数据包
            if isinstance(eth.data, dpkt.ip.IP) and isinstance(eth.data.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                packet_queue.put(("packet", 1))  # 计数数据包
                # 根据目标 MAC 判断上下行
                if eth.dst.lower() == mac_addr:
                    down_queue.put(len(pkt))
                else:
                    up_queue.put(len(pkt))
        except Exception:
            packet_queue.put(("dropped", 1))  # 记录解析失败的数据包

    # 开始捕获数据包
    try:
        for ts, pkt in pc:
            packet_handler(ts, pkt)
    except Exception as e:
        print(f"\n捕获数据包时出错: {e}", flush=True)
    finally:
        stats = pc.stats()
        print(f"\n最终统计: 数据包 {stats[0]}, 丢包 {stats[1]}, 内核丢包 {stats[2]}", flush=True)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n停止监控", flush=True)
    except Exception as e:
        print(f"错误: {e}", flush=True)