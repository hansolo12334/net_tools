import psutil
import win32gui
import win32ui
import win32con
import win32api
from PIL import Image
# import tkinter as tk
# from PIL import ImageTk




def extract_icon(exe_path):
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

    

# 根据进程PID获取图标
def get_process_icon(pid):
    """
    根据进程ID获取其EXE路径并提取图标。
    参数：
        pid (int): 进程ID
    返回：
        PIL.Image 或 None: 成功返回图标图像，失败返回None
    """
    try:
        proc = psutil.Process(pid)
        exe_path = proc.exe()  # 获取EXE路径
        return extract_icon(exe_path)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        print(f"无法访问进程 {pid} 的EXE文件")
        return None
    
    

# 获取所有进程的信息并提取图标
def get_process_info():
    """
    获取所有运行进程的PID、名称和图标。
    返回：
        list: 包含每个进程信息的字典列表
    """
    processes = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            icon = get_process_icon(proc.pid)
            processes.append({
                'pid': proc.pid,
                'name': proc.name(),
                'icon': icon
            })
        except Exception as e:
            print(f"获取进程 {proc.pid} 信息时出错: {e}")
    return processes


# 主程序：展示或保存图标
if __name__ == "__main__":
    # 获取进程信息
    processes = get_process_info()

    # 示例1：将图标保存到文件
    for proc in processes:
        if proc['icon']:
            proc['icon'].save(f"icon_{proc['pid']}.png")
            print(f"已保存图标: PID={proc['pid']}, 名称={proc['name']}")
        else:
            print(f"无图标: PID={proc['pid']}, 名称={proc['name']}")

    # 示例2：在Tkinter GUI中显示图标
    # root = tk.Tk()
    # root.title("正在运行的程序图标")
    # for proc in processes:
    #     if proc['icon']:
    #         tk_icon = ImageTk.PhotoImage(proc['icon'])
    #         label = tk.Label(root, image=tk_icon, text=f"{proc['name']} (PID: {proc['pid']})", compound="top")
    #         label.image = tk_icon  # 保留引用以防止垃圾回收
    #         label.pack()
    # root.mainloop()