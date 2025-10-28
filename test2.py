import scapy.all as scapy
import psutil
import socket
print("Scapy interfaces:", scapy.get_if_list())
print("Psutil interfaces:", list(psutil.net_if_addrs().keys()))
for iface in scapy.get_if_list():
    addrs = psutil.net_if_addrs().get(iface, [])
    print(f"Interface {iface}: {[addr.address for addr in addrs if addr.family == socket.AF_INET]}")
    
    
def get_active_interface():
    scapy_ifaces = scapy.get_if_list()
    psutil_ifaces = psutil.net_if_addrs()
    print(len(scapy_ifaces), len(psutil_ifaces.items()))
    for scapy_iface in scapy_ifaces:
        
        if 'Loopback' in scapy_iface:
            continue
        for psutil_iface, addrs in psutil_ifaces.items():
            for addr in addrs:
                print(addr)
                print("=============================")
                if addr.family == socket.AF_INET and addr.address != '127.0.0.1' and addr.address=='192.168.50.28':
                    try:
                        # 测试接口是否有流量
                        scapy.conf.iface = scapy_iface
                        pkt = scapy.sniff(iface=scapy_iface, count=1, timeout=0.5)  # 增加 timeout
                        print(pkt)
                        if pkt:
                            print(f"Interface {scapy_iface} is active with address {addr.address}")
                            return scapy_iface, [addr.address]
                    except Exception as e:
                        print(f"Interface {scapy_iface} test failed: {e}")
                        continue
    raise Exception("No valid network interface with traffic found")

get_active_interface()