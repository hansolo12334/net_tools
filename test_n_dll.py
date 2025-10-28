import ctypes
from ctypes import wintypes
import queue
import threading
import time
import psutil

# 定义 SECURITY_ATTRIBUTES 结构体
class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", wintypes.LPVOID),
        ("bInheritHandle", wintypes.BOOL),
    ]

# 加载 WFP 用户态 DLL
fwpuclnt = ctypes.WinDLL('fwpuclnt.dll')

# 定义 FwpmEngineOpen0
FwpmEngineOpen0 = fwpuclnt.FwpmEngineOpen0
FwpmEngineOpen0.argtypes = [wintypes.LPCWSTR, wintypes.UINT, ctypes.POINTER(SECURITY_ATTRIBUTES), ctypes.POINTER(wintypes.HANDLE)]
FwpmEngineOpen0.restype = wintypes.DWORD

# 定义 FwpmEngineClose0
FwpmEngineClose0 = fwpuclnt.FwpmEngineClose0
FwpmEngineClose0.argtypes = [wintypes.HANDLE]
FwpmEngineClose0.restype = wintypes.DWORD

def monitor_wfp(down_queue, up_queue):
    """监控 WFP 流量"""
    # 初始化 WFP 引擎
    engine_handle = wintypes.HANDLE()
    security_attributes = SECURITY_ATTRIBUTES()
    security_attributes.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
    security_attributes.lpSecurityDescriptor = None
    security_attributes.bInheritHandle = False

    # 使用默认认证服务
    result = FwpmEngineOpen0(None, 0, ctypes.byref(security_attributes), ctypes.byref(engine_handle))
    if result != 0:
        raise Exception(f"无法打开 WFP 引擎: {result} (检查管理员权限或 Windows 版本)")

    print("WFP 引擎已打开，正在配置流量监控...")

    # TODO: 添加 WFP 事件订阅
    # 参考: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmneteventsubscribe0
    try:
        while True:
            # 模拟流量数据（实际需通过 FwpmNetEventSubscribe0 获取）
            time.sleep(1)
            down_queue.put(0)  # 占位符
            up_queue.put(0)
    finally:
        FwpmEngineClose0(engine_handle)

def monitor(down_queue, up_queue):
    """统计并打印网速"""
    down_total = 0
    up_total = 0
    down_size = 0
    up_size = 0

    while True:
        start_time = time.time()
        while time.time() - start_time < 1.0:
            try:
                size = down_queue.get_nowait()
                down_size += size
                down_total += size
                down_queue.task_done()
            except queue.Empty:
                pass
            try:
                size = up_queue.get_nowait()
                up_size += size
                up_total += size
                up_queue.task_done()
            except queue.Empty:
                pass
            time.sleep(0.0001)

        down_speed = down_size / 1024.0 / 1024.0
        up_speed = up_size / 1024.0 / 1024.0
        down_total_mb = down_total / 1024.0 / 1024.0
        up_total_mb = up_total / 1024.0 / 1024.0

        print(f"\r下行: {down_speed:.2f} MB/s \t 上行: {up_speed:.2f} MB/s \t " f"累计下行: {down_total_mb:.2f} MB \t 累计上行: {up_total_mb:.2f} MB", end="", flush=True)

        down_size = 0
        up_size = 0

        cpu_usage = psutil.cpu_percent(interval=0.1)
        mem_usage = psutil.virtual_memory().percent
        if cpu_usage > 80 or mem_usage > 80:
            print(f"\n警告: 高 CPU 使用率 ({cpu_usage:.1f}%) 或内存使用率 ({mem_usage:.1f}%)", flush=True)

def main():
    # 检查管理员权限
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise Exception("请以管理员身份运行脚本")

    # 创建队列
    down_queue = queue.Queue(maxsize=20000)
    up_queue = queue.Queue(maxsize=20000)

    # 启动监控线程
    monitor_thread = threading.Thread(target=monitor, args=(down_queue, up_queue), daemon=True)
    monitor_thread.start()

    # 启动 WFP 监控
    try:
        monitor_wfp(down_queue, up_queue)
    except Exception as e:
        print(f"\nWFP 监控错误: {e}", flush=True)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n停止监控", flush=True)
    except Exception as e:
        print(f"错误: {e}", flush=True)