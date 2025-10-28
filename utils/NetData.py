
import os
import sys
import time
import ctypes
import psutil
import socket
import sqlite3
import threading
import pathlib
import scapy.all as scapy
from collections import defaultdict
from datetime import datetime, timedelta
import traceback
from PyQt5.QtCore import QThread ,pyqtSignal

import win32gui
import win32ui
import win32con
import win32api
from PIL import Image

class ExeData:
    def __init__(self, name, path, recv_bytes, send_bytes, recv_speed, send_speed, total_upload_bytes, total_download_bytes,has_icon=False, icon=None):
        self.name = name
        self.path = path
        self.recv_bytes = recv_bytes
        self.send_bytes = send_bytes
        self.recv_speed = recv_speed
        self.send_speed = send_speed

        self.exe_icon=self.extract_icon(path) if not has_icon else icon
        
        self.total_upload_bytes = total_upload_bytes
        self.total_download_bytes = total_download_bytes
        
    def __repr__(self):
        return f"ExeData(name={self.name}, path={self.path}, recv_bytes={self.recv_bytes}, send_bytes={self.send_bytes}, recv_speed={self.recv_speed}, send_speed={self.send_speed})"

    
    
    def extract_icon(self,exe_path):
        """
        从指定EXE文件中提取图标并返回PIL图像。
        参数：
            exe_path (str): 可执行文件的路径
        返回：
            PIL.Image 或 None: 成功返回图标图像，失败返回None
        """
        try:
            # 提取EXE文件中的大图标和小图标
            large, small = win32gui.ExtractIconEx(exe_path, 0)
            if len(large) <= 0:
                return None  # 如果没有大图标，返回None
            
            if small:
                win32gui.DestroyIcon(small[0])  # 销毁小图标句柄
        

            # 获取图标信息
            hdc = win32ui.CreateDCFromHandle(win32gui.GetDC(0))
            ico_x = win32api.GetSystemMetrics(win32con.SM_CXICON)
            ico_y = win32api.GetSystemMetrics(win32con.SM_CYICON)
            hbmp = win32ui.CreateBitmap()
            hbmp.CreateCompatibleBitmap(hdc, ico_x, ico_y)

            hdc = hdc.CreateCompatibleDC()
            hdc.SelectObject(hbmp)
            hdc.DrawIcon((0, 0), large[0])
            
        
            # 将位图转换为PIL图像
            img = Image.frombuffer('RGBA', (ico_x, ico_y), hbmp.GetBitmapBits(True), 'raw', 'BGRA', 0, 1)

            # 清理资源
            # hdc.DeleteDC()
            
            # win32gui.ReleaseDC(0, hdc)

            # win32gui.DeleteObject(hbmp.GetHandle())

            return img
        except Exception as e:
            print(f"无法从 {exe_path} 提取图标: {e}")
            return None
        
class NetDataRecorder(QThread):
    exe_data_signal = pyqtSignal(ExeData)
    
    def __init__(self):
        super(QThread, self).__init__()
        
        
        self.process_cache = {}
        self.process_cache_time = {}

        self.exe_icon_cache = {}

        self.traffic_data = defaultdict(lambda: {
                            'total_upload_bytes' : 0,
                            'total_download_bytes': 0,
                            'exe_path': 'unknown',
                            'per_second_download': defaultdict(int),
                            'per_minute_download': defaultdict(int),
                            'per_hour_download': defaultdict(int),
                            'per_day_download': defaultdict(int),
                            
                            'per_second_upload': defaultdict(int),
                            'per_minute_upload': defaultdict(int),     
                            'per_hour_upload': defaultdict(int),
                            'per_day_upload': defaultdict(int)
                            })
        self.second_key=None
        self.last_time=datetime.now()
        
        self.packet_count = 0
        self.total_bytes = 0
        # 优化 Scapy 配置
        scapy.conf.bufsize=104857600  # 增加缓冲区
        scapy.conf.use_pcap = True  # 使用 Npcap
        
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        
        self.start_summary_thread()
        
    
    def start_summary_thread(self):
        """每秒汇总并发射信号"""
        def summarize():
            while not self.stop_event.is_set():
                try:
                    # now = datetime.now()
                    # second_key = now.strftime('%Y-%m-%d %H:%M:%S')
                    # 遍历所有进程的每秒数据
                    with self.lock:
                        if self.second_key is None:
                            continue
                        for process_name, data in list(self.traffic_data.items()):
                            send_bytes = data['per_second_upload'].get(self.second_key, 0)
                            recv_bytes = data['per_second_download'].get(self.second_key, 0)
                            # 发射信号
                            
                            emmit_data = ExeData(
                                name=process_name,
                                path=data.get('exe_path'),
                                recv_bytes=round(recv_bytes*8,2),
                                send_bytes=round(send_bytes*8,2),
                                recv_speed=round(recv_bytes*8 / 1048576,2),  # 转换为 MB/s
                                send_speed=round(send_bytes*8 / 1048576,2),  # 转换为 MB/s
                                total_upload_bytes=round(data['total_upload_bytes']*8/ 1048576,2),
                                total_download_bytes=round(data['total_download_bytes']*8/ 1048576,2),
                                has_icon=process_name in self.exe_icon_cache,
                                icon=self.exe_icon_cache[process_name] if process_name in self.exe_icon_cache else None
                            )
                            if process_name not in self.exe_icon_cache:
                                self.exe_icon_cache[process_name] =  emmit_data.exe_icon 
                            
                            # if process_name=="chrome.exe":
                            #     print(f"chrome.exe: {round(recv_bytes / 1048576,2)}")
                            self.exe_data_signal.emit(emmit_data)
                            
                            
                        print(f"Summary at {self.second_key}: Processed {self.packet_count} packets, Total {self.total_bytes / 1048576:.2f} MB")
                        self.packet_count = 0  # 重置计数
                        self.total_bytes = 0
                    # 清理旧数据（保留最近 5 分钟）
                    # cutoff = (now - timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S')
                    # for process in self.traffic_data:
                    #     self.traffic_data[process]['per_second_upload'] = {
                    #         k: v for k, v in self.traffic_data[process]['per_second_upload'].items()
                    #         if k > cutoff or k.endswith('_recv') and k[:-5] > cutoff
                    #     }
                    #     self.traffic_data[process]['per_second_download'] = {
                    #         k: v for k, v in self.traffic_data[process]['per_second_download'].items()
                    #         if k > cutoff or k.endswith('_recv') and k[:-5] > cutoff
                    #     }
                    time.sleep(1)
                except Exception as e:
                    print(f"Error in summarize: {e}")
                    
        threading.Thread(target=summarize, daemon=True).start()
        
        
        
    def get_process_by_port(self, local_port, ip_version='IPv4'):
        """根据端口和IP版本获取进程路径"""
        now = time.time()
        cache_key = (local_port, ip_version)
        if cache_key in self.process_cache and now - self.process_cache_time.get(cache_key, 0) < 180:  # 延长缓存时间
            return self.process_cache[cache_key]
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr and conn.laddr.port == local_port:
                    if (ip_version == 'IPv4' and conn.family == socket.AF_INET) or  (ip_version == 'IPv6' and conn.family == socket.AF_INET6):
                        try:
                            proc = psutil.Process(conn.pid)
                            process_exe = proc.exe()
                            if process_exe and os.path.exists(process_exe):
                                self.process_cache[cache_key] = process_exe
                                self.process_cache_time[cache_key] = now
                                print(f"Found process for port {local_port} ({ip_version}): {process_exe}")
                                return process_exe
                            else:
                                print(f"Invalid process_exe for port {local_port} ({ip_version}): {process_exe}")
                                self.process_cache[cache_key] = "unknown"
                                self.process_cache_time[cache_key] = now
                                return "unknown"
                        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                            print(f"Error accessing process for port {local_port} ({ip_version}): {e}")
                            self.process_cache[cache_key] = "unknown"
                            self.process_cache_time[cache_key] = now
                            return "unknown"
            print(f"No process found for port {local_port} ({ip_version})")
            self.process_cache[cache_key] = "unknown"
            self.process_cache_time[cache_key] = now
            return "unknown"
        except psutil.AccessDenied as e:
            print(f"Warning: Access denied to network connections for port {local_port} ({ip_version}): {e}")
            self.process_cache[cache_key] = "unknown"
            self.process_cache_time[cache_key] = now
            return "unknown"
        except Exception as e:
            print(f"Error in get_process_by_port for port {local_port} ({ip_version}): {e}")
            traceback.print_exc()
            self.process_cache[cache_key] = "unknown"
            self.process_cache_time[cache_key] = now
            return "unknown"
    
    def process_packet(self,packet:scapy.Packet, local_ips:list, local_ipv6s:list):
        try:
            self.packet_count += 1
            process_name = "unknown"
            packet_size = len(packet)
            self.total_bytes += packet_size
            
            now = datetime.now()
            second_key = now.strftime('%Y-%m-%d %H:%M:%S')
            minute_key = now.strftime('%Y-%m-%d %H:%M')
            hour_key = now.strftime('%Y-%m-%d %H')
            day_key = now.strftime('%Y-%m-%d')
            domain = None
            
            self.second_key=second_key
            # IPv4 数据包
            if packet.haslayer(scapy.IP):
                ip_layer = packet[scapy.IP]
                src_ip, dst_ip = ip_layer.src, ip_layer.dst
                if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
                    local_port = None
                    if src_ip in local_ips:
                        local_port = packet[scapy.TCP].sport if packet.haslayer(scapy.TCP) else packet[scapy.UDP].sport
                        process_exe = self.get_process_by_port(local_port, 'IPv4')
                        if process_exe and process_exe != "unknown" and os.path.exists(process_exe):
                            process_name= os.path.basename(process_exe)
                            with self.lock:
                                self.traffic_data[process_name]['per_second_upload'][second_key] += packet_size
                                self.traffic_data[process_name]['per_minute_upload'][minute_key] += packet_size
                                self.traffic_data[process_name]['per_hour_upload'][hour_key] += packet_size
                                self.traffic_data[process_name]['per_day_upload'][day_key] += packet_size
                                self.traffic_data[process_name]['total_upload_bytes'] += packet_size
                                self.traffic_data[process_name]['exe_path'] = process_exe

                                
                                        
                            # print(f"上传 IPv4 Packet: {src_ip} -> {dst_ip}, Size: {packet_size} bytes ,  process_exe: {process_name}")
                            # emmit_data = ExeData(
                            #     name=os.path.basename(process_exe),
                            #     path=process_exe,
                            #     recv_bytes=self.traffic_data[process_name]['per_second'][second_key],
                            #     send_bytes=0,  # 这里可以根据需要计算发送字节数
                            #     recv_speed=0,  # 这里可以根据需要计算接收速度
                            #     send_speed=packet_size   # 这里可以根据需要计算发送速度
                            # )
                            # self.exe_data_signal.emit(emmit_data)
                        
                    elif dst_ip in local_ips:
                        local_port = packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else packet[scapy.UDP].dport
                        process_exe = self.get_process_by_port(local_port, 'IPv4')
                        if process_exe and process_exe != "unknown" and os.path.exists(process_exe):
                            process_name= os.path.basename(process_exe)
                            with self.lock:
                                self.traffic_data[process_name]['per_second_download'][second_key] += packet_size
                                self.traffic_data[process_name]['per_minute_download'][minute_key] += packet_size
                                self.traffic_data[process_name]['per_hour_download'][hour_key] += packet_size
                                self.traffic_data[process_name]['per_day_download'][day_key] += packet_size
                                self.traffic_data[process_name]['total_download_bytes'] += packet_size
                                self.traffic_data[process_name]['exe_path'] = process_exe
                                
                                
                                # print( (now-self.last_time).seconds)
                                if (now-self.last_time).seconds ==1:
                                    print(f"每秒数据更新 {self.traffic_data[process_name]['per_second_upload'][second_key]}")
                                    self.last_time = now
                    
                            # print(f"下载 IPv4 Packet: {src_ip} -> {dst_ip}, Size: {packet_size} bytes , process_name: {process_name}")
                            # emmit_data = ExeData(
                            #     name=os.path.basename(process_exe),
                            #     path=process_exe,
                            #     recv_bytes=self.traffic_data[process_name]['per_second'][second_key],
                            #     send_bytes=0,  # 这里可以根据需要计算发送字节数
                            #     recv_speed=packet_size,  # 这里可以根据需要计算接收速度
                            #     send_speed=0   # 这里可以根据需要计算发送速度
                            # )
                            # self.exe_data_signal.emit(emmit_data)
            # IPv6 数据包
            
            
        except Exception as e:
            print(f"Error processing packet: {e}")
            
    
    def get_active_interface(self):
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
    def capture_traffic(self):
        try:
            iface, local_ips, local_ipv6s = self.get_active_interface()
            print(f"Capturing on interface: {iface}")
            print(f"IPv4 IPs: {local_ips}")
            print(f"IPv6 IPs: {local_ipv6s}")
            scapy.sniff(iface=iface, 
                        prn=lambda pkt: self.process_packet(pkt, local_ips, local_ipv6s), 
                        store=False, 
                        filter="ip or ip6",
                        timeout=None, 
                        stop_filter=lambda x: self.stop_event.is_set()
                        )
        except Exception as e:
            print(f"Error capturing packets: {e}")
            self.stop_event.set()
            sys.exit(1)
            
    def run(self):
        self.capture_traffic()
        return super().run()
    
    
    def stop(self):
        print("Stopping packet capture...")
        self.stop_event.set()
        # 等待线程自然结束，不需要调用 join() 因为这可能在主线程中调用
        # self.join() 会在主线程中等待子线程结束