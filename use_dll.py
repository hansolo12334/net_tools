import ctypes
import json
import time
import os
import shutil
from ctypes import c_char_p, c_int, c_uint32

# 设置路径
build_path = r"D:\project\net_tools\build"
dll_path = os.path.join(build_path, "network_monitor_dll.dll")

# 复制依赖 DLL
npcap_path = r"C:\Program Files\Npcap\wpcap.dll"
mingw_dlls = [
    r"D:\MSYS2\ucrt64\bin\libgcc_s_seh-1.dll",
    r"D:\MSYS2\ucrt64\bin\libstdc++-6.dll",
    r"D:\MSYS2\ucrt64\bin\libwinpthread-1.dll"
]
for dll in [npcap_path] + mingw_dlls:
    if os.path.exists(dll):
        dst = os.path.join(build_path, os.path.basename(dll))
        if not os.path.exists(dst):
            shutil.copy(dll, build_path)
            print(f"已复制 {os.path.basename(dll)} 到 {build_path}")
    else:
        print(f"警告: {dll} 不存在，请确认安装")

# 添加 build 目录到 PATH
os.environ["PATH"] += os.pathsep + build_path

# 加载 DLL
try:
    dll = ctypes.WinDLL(dll_path)
except WindowsError as e:
    print(f"加载 DLL 失败: {e}")
    print("请检查文件路径、依赖项或以管理员身份运行")
    exit(1)

# 定义函数原型
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

# 启动监控（网卡编号 7）
result = start_monitor(7)
try:
    info = json.loads(result.decode())
except json.JSONDecodeError:
    print(f"启动失败: {result.decode()}")
    exit(1)

if "error" in info:
    print(f"错误: {info['error']}")
    exit(1)
print(f"启动监控: {info['adapter']} ({info['description']})")
print(f"MAC: {info['mac']}, IP: {info['ip']}")

try:
    while True:
        total = json.loads(get_total_traffic().decode())
        print("\n=== 总体流量 ===")
        print(f"下行: {total['down_speed_mbs']:.2f} MB/s, 上行: {total['up_speed_mbs']:.2f} MB/s")
        print(f"累计下行: {total['total_down_mb']:.2f} MB, 累计上行: {total['total_up_mb']:.2f} MB")

        processes = json.loads(get_processes().decode())
        print("\n=== 进程流量 ===")
        for proc in processes:
            pid = proc["pid"]
            traffic = json.loads(get_process_traffic(pid).decode())
            if "error" not in traffic:
                print(f"{traffic['name']} (PID: {pid}): "
                      f"下行: {traffic['down_speed_mbs']:.2f} MB/s, "
                      f"上行: {traffic['up_speed_mbs']:.2f} MB/s, "
                      f"累计下行: {traffic['total_down_mb']:.2f} MB, "
                      f"累计上行: {traffic['total_up_mb']:.2f} MB", flush=True)

        time.sleep(1)
except KeyboardInterrupt:
    stop_monitor()
    print("监控已停止")
except Exception as e:
    stop_monitor()
    print(f"运行时错误: {e}")