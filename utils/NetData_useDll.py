
import os
import sys
import time
import ctypes
import psutil
import socket
import sqlite3
import threading
import pathlib
# import scapy.all as scapy
from collections import defaultdict
from datetime import datetime, timedelta
import traceback
from PyQt5.QtCore import QThread ,pyqtSignal

import win32gui
import win32ui
import win32con
import win32api
from win32com.client import Dispatch
import pythoncom

from PIL import Image

from ctypes import c_char_p, c_int, c_uint32
import shutil
import json



class ExeData:
    def __init__(self, 
                 name, path, 
                 recv_bytes, send_bytes, 
                 recv_speed, send_speed,
                 recv_packets,send_packets,
                 ipv4_recv_bytes, ipv4_send_bytes,
                 ipv6_recv_bytes, ipv6_send_bytes,
                 has_icon=False, icon=None):
        self.name = name
        self.path = path
        
        #不固定数值
        self.recv_bytes = recv_bytes
        self.send_bytes = send_bytes
        self.recv_speed = recv_speed
        self.send_speed = send_speed
        
        self.recv_packets = recv_packets
        self.send_packets= send_packets
        
        self.ipv4_recv_bytes = ipv4_recv_bytes
        self.ipv4_send_bytes = ipv4_send_bytes
        
        self.ipv6_recv_bytes = ipv6_recv_bytes
        self.ipv6_send_bytes = ipv6_send_bytes
        
        self.send_and_recv_bytes = recv_bytes + send_bytes
        self.send_and_recv_packets =self.recv_packets+ self.send_packets
        
        self.max_download_speed = 0
        self.max_upload_speed = 0
        
        self.evg_download_speed = 0
        self.evg_upload_speed = 0
        
        self.process_start_time= datetime.now()
        self.process_last_time = None
        
        #固定数值
        self.product_name=None
        self.product_version= None
        self.file_description = None
        self.company_name = None
        
        self.exe_icon=self.extract_icon(path) if not has_icon else icon
        

        
        
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
        
        
    def get_exe_info_win32com(self):
        """使用 win32com 提取文件信息
        """
        try:
            pythoncom.CoInitialize()
            shell = Dispatch('Shell.Application')
            folder_path, file_name = os.path.split(self.path)
            folder = shell.NameSpace(folder_path)
            item = folder.ParseName(file_name)
            
            # 存储提取的属性
            result = {'FileDescription': 'N/A', 'CompanyName': 'N/A', 'FileVersion': 'N/A'}
            
            # 遍历所有可能的属性（0-300）
            for i in [297,166,34,33]:
                value = folder.GetDetailsOf(item, i)
                if value:
                    # 调试输出所有非空属性
                    # print(f"属性 {i}: {value}")
                    # 190=文件名称，166=版本，34=文件描述 33 公司名称
                    if i == 297 and value: #190=文件名称
                        result['FileName'] = value
                    elif i == 166 and value:  # 版本，34
                        result['FileVersion'] = value
                    elif i == 34 and value:  # 文件描述
                        result['FileDescription'] = value
                    elif i == 33 and value:  # 公司名称
                        result['CompanyName'] = value
                        
            # for i in range(300):
            #     value = folder.GetDetailsOf(item, i)
            #     if value:
            #         # 调试输出所有非空属性
            #         print(f"属性 {i}: {value}")
            #         # 常见属性：21=文件说明，34=公司名称，11=文件版本
            #         if i == 21 and value:  # 文件说明
            #             result['FileDescription'] = value
            #         elif i == 34 and value:  # 公司名称
            #             result['CompanyName'] = value
            #         elif i == 11 and value:  # 文件版本
            #             result['FileVersion'] = value
            self.product_name=result["FileName"]
            self.product_version= result['FileVersion']
            self.file_description = result["FileDescription"]
            self.company_name = result["CompanyName"]
            # print(f"提取到的文件信息: 名称={result['FileName']}, 版本={result['FileVersion']}, 描述={result['FileDescription']}, 公司={result['CompanyName']}")

        
        except Exception as e:
            return {'Error': f'win32com 无法获取文件信息: {str(e)}'}
        
    def extract_imformation(self):
        """
        从EXE文件中提取产品版本、文件描述和公司名称。
        返回：
            tuple: 包含产品版本、文件描述和公司名称的元组
        """
        try:
            info = win32api.GetFileVersionInfo(self.path, '\\')
            
            # 获取版本号
            ms = info['FileVersionMS']
            ls = info['FileVersionLS']
            version = f"{win32api.HIWORD(ms)}.{win32api.LOWORD(ms)}.{win32api.HIWORD(ls)}.{win32api.LOWORD(ls)}"
            
            # 获取文件说明和公司名称
            # lang, codepage = win32api.GetFileVersionInfo(self.path, '\\VarFileInfo\\Translation')[0]
            translations = win32api.GetFileVersionInfo(self.path, '\\VarFileInfo\\Translation')
        
            # 尝试每个语言/代码页组合
            for lang, codepage in translations:
                try:
                    str_info = f'\\StringFileInfo\\{lang:04x}{codepage:04x}\\'
                    file_description = win32api.GetFileVersionInfo(self.path, str_info + 'FileDescription') or 'N/A'
                    company_name = win32api.GetFileVersionInfo(self.path, str_info + 'CompanyName') or 'N/A'
                    
                    # 如果成功获取到有效信息，返回结果
                    if file_description != 'N/A' or company_name != 'N/A':
                        # print(f"提取到的文件信息: 版本={version}, 描述={file_description}, 公司={company_name}")
                        return version, file_description, company_name
                except:
                    # 如果当前语言/代码页失败，继续尝试下一个
                    continue
            
        
        
            file_description = win32api.GetFileVersionInfo(self.path, str_info + 'FileDescription') or 'N/A'
            company_name = win32api.GetFileVersionInfo(self.path, str_info + 'CompanyName') or 'N/A'
            return version, file_description, company_name
        
        
        
        except Exception as e:
            return {'Error': f'无法获取文件信息: {str(e)}'}


class ExeCatches:
    def __init__(self):
        self.name = []
        self.path = []
        self.icon=[]
    
    def add_data(self,exe_data: ExeData):
        """
        添加ExeData对象到列表中。
        参数：
            exe_data (ExeData): 要添加的ExeData对象
        """
        self.name.append(exe_data.name)
        self.path.append(exe_data.path)
        self.icon.append(exe_data.exe_icon)
    
    def get_path(self, name):
        """
        根据名称获取路径。
        参数：
            name (str): 要查找的名称
        返回：
            str: 对应的路径，如果未找到则返回None
        """
        if name in self.name:
            index = self.name.index(name)
            return self.path[index]
        return None
        
    def get_icon(self, name):
        """
        根据名称获取图标。
        参数：
            name (str): 要查找的名称
        返回：
            PIL.Image: 对应的图标，如果未找到则返回None
        """
        if name in self.name:
            index = self.name.index(name)
            return self.icon[index]
        return None
    
    
    
class NetDataRecorder(QThread):
    exe_data_signal = pyqtSignal(ExeData)
    
    def __init__(self):
        super(QThread, self).__init__()
        
        
        self.process_cache = {}
        self.process_cache_time = {}

        self.exe_catches = ExeCatches()

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
        
        

        
        self.start_monitor, self.stop_monitor, self.get_processes, self.get_process_traffic, self.get_total_traffic = self.init_dll()
        
   
     
    
    def init_dll(self):
        build_path = "./build"
        dll_path = os.path.join(build_path, "network_monitor_dll.dll")
        # npcap_path = r"C:\Program Files\Npcap\wpcap.dll"
        mingw_dlls = [
            r"D:\MSYS2\ucrt64\bin\libgcc_s_seh-1.dll",
            r"D:\MSYS2\ucrt64\bin\libstdc++-6.dll",
            r"D:\MSYS2\ucrt64\bin\libwinpthread-1.dll"
        ]
        for dll in  mingw_dlls:
            if os.path.exists(dll):
                dst = os.path.join(build_path, os.path.basename(dll))
                if not os.path.exists(dst):
                    shutil.copy(dll, build_path)
                    print(f"已复制 {os.path.basename(dll)} 到 {build_path}")
            else:
                print(f"警告: {dll} 不存在，请确认安装")
                
        os.environ["PATH"] += os.pathsep + build_path
        # 加载 DLL
        try:
            dll = ctypes.WinDLL(dll_path)
        except WindowsError as e:
            print(f"加载 DLL 失败: {e}")
            print("请检查文件路径、依赖项或以管理员身份运行")
            exit(1)

        start_monitor = dll.start_monitor
        start_monitor.argtypes = [c_int]
        start_monitor.restype = c_char_p

        stop_monitor = dll.stop_monitor
        stop_monitor.argtypes = []
        stop_monitor.restype = None

        get_processes = dll.get_processes
        get_processes.restype = c_char_p

        get_process_traffic = dll.get_process_traffic
        get_process_traffic.argtypes = [c_uint32]
        get_process_traffic.restype = c_char_p

        get_total_traffic = dll.get_total_traffic
        get_total_traffic.restype = c_char_p
        
        
        return start_monitor, stop_monitor, get_processes, get_process_traffic, get_total_traffic
    
 
    
    # def get_active_interface(self):
    #     target_psutil_iface = '以太网 3'
    #     scapy_ifaces = scapy.get_if_list()
    #     psutil_ifaces = psutil.net_if_addrs()
        
    #     if target_psutil_iface not in psutil_ifaces:
    #         raise Exception(f"Interface {target_psutil_iface} not found in psutil interfaces")
        
    #     local_ips = []
    #     local_ipv6s = []
    #     for addr in psutil_ifaces[target_psutil_iface]:
    #         if addr.family == socket.AF_INET and addr.address != '127.0.0.1':
    #             local_ips.append(addr.address)
    #         elif addr.family == socket.AF_INET6 and not addr.address.startswith('fe80::'):
    #             local_ipv6s.append(addr.address)
        
    #     if not (local_ips or local_ipv6s):
    #         raise Exception(f"No valid IP addresses found for {target_psutil_iface}")
        
    #     for scapy_iface in scapy_ifaces:
    #         if 'Loopback' in scapy_iface:
    #             continue
    #         try:
    #             scapy.conf.iface = scapy_iface
    #             iface_ip = scapy.get_if_addr(scapy_iface)
    #             if iface_ip in local_ips or iface_ip in local_ipv6s:
    #                 return scapy_iface, local_ips, local_ipv6s
    #         except:
    #             continue
        
    #     raise Exception("No matching Scapy interface found for 以太网 3")
    
    
    # 捕获数据包
    def capture_traffic(self):
        try:
            success=self.start_monitor(7)
            success=json.loads(success.decode())
            if not success.get("success"):
                print("启动网络监控失败,请检查是否有管理员权限或DLL文件是否正确")
                sys.exit(1)
                
            print("网络监控已启动")
            while True:
                # 获取当前时间的秒级别字符串
                now = datetime.now()
                self.second_key = now.strftime('%Y-%m-%d %H:%M:%S')
                
                # 获取进程流量数据
                processes = json.loads(self.get_processes().decode())
                
                for proc in processes:
                    pid = proc["pid"]
                    traffic = json.loads(self.get_process_traffic(pid).decode())
                    if "error" not in traffic:
        
                        name=traffic['name']
                        if name not in self.exe_catches.name:
                            try:
                                proc = psutil.Process(pid)
                                process_exe = proc.exe()
                                if name == "Unknown":
                                    name = process_exe.split(os.sep)[-1]  
                                    traffic['name']= name  
                            except psutil.NoSuchProcess:
                                # print(f"Process {pid} no longer exists.")
                                continue
                        else:
                            process_exe = self.exe_catches.get_path(name)

                        if process_exe is None or not os.path.exists(process_exe):
                            continue
                        
                        
                        emmit_data = ExeData(
                                name=name,
                                path=process_exe,
                                recv_bytes=traffic['total_down_mb'], 
                                send_bytes=traffic['total_up_mb'],  
                                recv_speed= traffic['down_speed_mbs'],
                                send_speed=traffic['up_speed_mbs'],
                                send_packets=traffic['up_packets'],
                                recv_packets=traffic['down_packets'],
                                ipv4_recv_bytes= traffic['down_bytes_ipv4'],
                                ipv4_send_bytes=traffic['up_bytes_ipv4'],
                                ipv6_recv_bytes=traffic['down_bytes_ipv6'],
                                ipv6_send_bytes=traffic['up_bytes_ipv6'],
                                has_icon=name in self.exe_catches.name,
                                icon=self.exe_catches.get_icon(name) if name in self.exe_catches.name else None
                            )
                        
                        if name not in self.exe_catches.name:
                            self.exe_catches.add_data(emmit_data)   
                            
                        self.exe_data_signal.emit(emmit_data)
                        
                        
                        # print(f"{traffic['name']} (PID: {pid}): "
                        #     f"下行: {traffic['down_speed_mbs']:.2f} MB/s, "
                        #     f"上行: {traffic['up_speed_mbs']:.2f} MB/s, "
                        #     f"累计下行: {traffic['total_down_mb']:.2f} MB, "
                        #     f"累计上行: {traffic['total_up_mb']:.2f} MB", flush=True)
            
                time.sleep(1)  # 每秒更新一次
           
        except Exception as e:
            print(f"Error capturing packets: {e}")
            self.stop_monitor()
            sys.exit(1)
            
    def run(self):
        self.capture_traffic()
        return super().run()
    
    
    def stop(self):
        
        print("Stopping packet capture...")
        self.stop_monitor()
        # 等待线程自然结束，不需要调用 join() 因为这可能在主线程中调用
        # self.join() 会在主线程中等待子线程结束
        
        
        
# if __name__ == "__main__":
#     recorder = NetDataRecorder()
#     result = recorder.start_monitor(7)
#     print(json.loads(result.decode()))
    
    # recorder.start()
    # try:
    #     while True:
    #         time.sleep(1)
    # except KeyboardInterrupt:
    #     recorder.stop()
    #     print("Recorder stopped.")