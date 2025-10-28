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
from time import sleep
from mitmproxy.tools.main import mitmdump


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
    
if __name__ == "__main__":
    if not setup_port_forwarding():
        print("Failed to set up port forwarding. Exiting.")
        sys.exit(1)
        
        
    
    
    # 注册清理函数
    register_cleanup()
    
    sleep(50)  # 等待端口转发生效