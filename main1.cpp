#include <pcap.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <string>
#include <vector>
#include <map>
#include <iostream>
#include <psapi.h>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")

// 全局变量
std::atomic<uint64_t> downBytes(0);
std::atomic<uint64_t> upBytes(0);
std::mutex printMutex;
std::string localMac;
std::string localIp;

// 进程流量统计
struct ProcessTraffic {
    std::atomic<uint64_t> downBytes{0};
    std::atomic<uint64_t> upBytes{0};
};
std::map<DWORD, ProcessTraffic> processTraffic;
std::mutex processTrafficMutex;

// 连接信息（IP+端口 -> PID）
struct ConnectionKey {
    std::string localIp;
    uint16_t localPort;
    std::string remoteIp;
    uint16_t remotePort;
    bool operator<(const ConnectionKey& other) const {
        return std::tie(localIp, localPort, remoteIp, remotePort) <
               std::tie(other.localIp, other.localPort, other.remoteIp, other.remotePort);
    }
};
std::map<ConnectionKey, DWORD> connectionMap;
std::mutex connectionMapMutex;

// 获取进程名称
std::string getProcessName(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return "Unknown";
    char name[MAX_PATH] = {0};
    GetProcessImageFileNameA(hProcess, name, MAX_PATH);
    CloseHandle(hProcess);
    std::string result = name;
    size_t pos = result.find_last_of("\\");
    return pos != std::string::npos ? result.substr(pos + 1) : result;
}

// 获取本地 MAC 和 IP 地址
bool getLocalMacAndIp(const char* iface, std::string& mac, std::string& ip) {
    PIP_ADAPTER_INFO pAdapterInfo;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
    }

    bool found = false;
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR) {
        std::string ifaceName = iface;
        if (ifaceName.find("\\Device\\NPF_") == 0) {
            ifaceName = ifaceName.substr(12);
        }

        printf("调试: 规范化后的网卡名称: %s\n", ifaceName.c_str());
        printf("调试: 可用适配器列表:\n");
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter) {
            printf("  AdapterName: %s, MAC: %02X:%02X:%02X:%02X:%02X:%02X, IP: %s\n",
                   pAdapter->AdapterName,
                   pAdapter->Address[0], pAdapter->Address[1], pAdapter->Address[2],
                   pAdapter->Address[3], pAdapter->Address[4], pAdapter->Address[5],
                   pAdapter->IpAddressList.IpAddress.String);
            if (std::string(pAdapter->AdapterName) == ifaceName) {
                char macStr[18];
                sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X",
                        pAdapter->Address[0], pAdapter->Address[1], pAdapter->Address[2],
                        pAdapter->Address[3], pAdapter->Address[4], pAdapter->Address[5]);
                mac = macStr;
                ip = pAdapter->IpAddressList.IpAddress.String;
                found = true;
            }
            pAdapter = pAdapter->Next;
        }
    }
    free(pAdapterInfo);
    return found;
}

// 更新连接表
void updateConnectionMap() {
    // 获取 TCP 连接
    PMIB_TCPTABLE2 pTcpTable = nullptr;
    ULONG ulSize = 0;
    if (GetTcpTable2(nullptr, &ulSize, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
        pTcpTable = (PMIB_TCPTABLE2)malloc(ulSize);
        if (GetTcpTable2(pTcpTable, &ulSize, FALSE) == NO_ERROR) {
            std::lock_guard<std::mutex> lock(connectionMapMutex);
            for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
                auto& row = pTcpTable->table[i];
                ConnectionKey key;
                char localIp[16], remoteIp[16];
                sprintf(localIp, "%d.%d.%d.%d",
                        (row.dwLocalAddr >> 0) & 0xFF, (row.dwLocalAddr >> 8) & 0xFF,
                        (row.dwLocalAddr >> 16) & 0xFF, (row.dwLocalAddr >> 24) & 0xFF);
                sprintf(remoteIp, "%d.%d.%d.%d",
                        (row.dwRemoteAddr >> 0) & 0xFF, (row.dwRemoteAddr >> 8) & 0xFF,
                        (row.dwRemoteAddr >> 16) & 0xFF, (row.dwRemoteAddr >> 24) & 0xFF);
                key.localIp = localIp;
                key.localPort = ntohs((uint16_t)row.dwLocalPort);
                key.remoteIp = remoteIp;
                key.remotePort = ntohs((uint16_t)row.dwRemotePort);
                connectionMap[key] = row.dwOwningPid;
            }
        }
        free(pTcpTable);
    }

    // 获取 UDP 连接（带 PID）
    PMIB_UDPTABLE_OWNER_PID pUdpTable = nullptr;
    ulSize = 0;
    if (GetExtendedUdpTable(nullptr, &ulSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == ERROR_INSUFFICIENT_BUFFER) {
        pUdpTable = (PMIB_UDPTABLE_OWNER_PID)malloc(ulSize);
        if (GetExtendedUdpTable(pUdpTable, &ulSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            std::lock_guard<std::mutex> lock(connectionMapMutex);
            for (DWORD i = 0; i < pUdpTable->dwNumEntries; i++) {
                auto& row = pUdpTable->table[i];
                ConnectionKey key;
                char localIp[16];
                sprintf(localIp, "%d.%d.%d.%d",
                        (row.dwLocalAddr >> 0) & 0xFF, (row.dwLocalAddr >> 8) & 0xFF,
                        (row.dwLocalAddr >> 16) & 0xFF, (row.dwLocalAddr >> 24) & 0xFF);
                key.localIp = localIp;
                key.localPort = ntohs((uint16_t)row.dwLocalPort);
                key.remoteIp = "0.0.0.0"; // UDP 可能无远程地址
                key.remotePort = 0;
                connectionMap[key] = row.dwOwningPid;
            }
        }
        free(pUdpTable);
    }
}

// 数据包处理回调
void packetHandler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    struct ether_header {
        u_char dest[6];
        u_char src[6];
        u_short type;
    } *eth = (ether_header*)pkt_data;

    if (ntohs(eth->type) == 0x0800) {
        struct ip_header {
            u_char ver_ihl;
            u_char tos;
            u_short tlen;
            u_short id;
            u_short flags_fo;
            u_char ttl;
            u_char proto;
            u_short csum;
            u_char src[4];
            u_char dst[4];
        } *ip = (ip_header*)(pkt_data + 14);

        if (ip->proto == 6 || ip->proto == 17) {
            struct tcp_udp_header {
                u_short src_port;
                u_short dst_port;
            } *transport = (tcp_udp_header*)(pkt_data + 14 + ((ip->ver_ihl & 0x0F) * 4));

            // 确定上下行
            bool isDownlink = false;
            if (!localMac.empty()) {
                std::string destMac;
                char mac[18];
                sprintf(mac, "%02X:%02X:%02X:%02X:%02X:%02X",
                        eth->dest[0], eth->dest[1], eth->dest[2],
                        eth->dest[3], eth->dest[4], eth->dest[5]);
                destMac = mac;
                isDownlink = (destMac == localMac);
            } else {
                char dstIp[16];
                sprintf(dstIp, "%d.%d.%d.%d", ip->dst[0], ip->dst[1], ip->dst[2], ip->dst[3]);
                isDownlink = (std::string(dstIp) == localIp);
            }

            // 查找 PID
            ConnectionKey key;
            char srcIp[16], dstIp[16];
            sprintf(srcIp, "%d.%d.%d.%d", ip->src[0], ip->src[1], ip->src[2], ip->src[3]);
            sprintf(dstIp, "%d.%d.%d.%d", ip->dst[0], ip->dst[1], ip->dst[2], ip->dst[3]);
            key.localIp = isDownlink ? dstIp : srcIp;
            key.localPort = ntohs(isDownlink ? transport->dst_port : transport->src_port);
            key.remoteIp = isDownlink ? srcIp : dstIp;
            key.remotePort = ntohs(isDownlink ? transport->src_port : transport->dst_port);

            DWORD pid = 0;
            {
                std::lock_guard<std::mutex> lock(connectionMapMutex);
                auto it = connectionMap.find(key);
                if (it != connectionMap.end()) {
                    pid = it->second;
                } else if (ip->proto == 17) { // UDP 回退
                    key.remoteIp = "0.0.0.0";
                    key.remotePort = 0;
                    it = connectionMap.find(key);
                    if (it != connectionMap.end()) {
                        pid = it->second;
                    }
                }
            }

            // 更新流量
            if (pid != 0) {
                std::lock_guard<std::mutex> lock(processTrafficMutex);
                if (isDownlink) {
                    processTraffic[pid].downBytes += header->len;
                } else {
                    processTraffic[pid].upBytes += header->len;
                }
            }

            // 更新总体流量
            if (isDownlink) {
                downBytes += header->len;
            } else {
                upBytes += header->len;
            }
        }
    }
}

void MonitorThread() {
    std::map<DWORD, uint64_t> lastDown, lastUp;
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        uint64_t currentDown = downBytes.load();
        uint64_t currentUp = upBytes.load();
        double downSpeed = (currentDown - lastDown[0]) / 1024.0 / 1024.0; // MB/s
        double upSpeed = (currentUp - lastUp[0]) / 1024.0 / 1024.0; // MB/s
        double totalDownMB = currentDown / 1024.0 / 1024.0;
        double totalUpMB = currentUp / 1024.0 / 1024.0;

        // 更新连接表
        updateConnectionMap();

        // 打印总体流量
        std::lock_guard<std::mutex> lock(printMutex);
        printf("\n=== 总体流量 ===\n");
        printf("下行: %.2f MB/s \t 上行: %.2f MB/s \t 累计下行: %.2f MB \t 累计上行: %.2f MB\n",
               downSpeed, upSpeed, totalDownMB, totalUpMB);

        // 打印进程流量
        printf("=== 进程流量 ===\n");
        {
            std::lock_guard<std::mutex> lock(processTrafficMutex);
            for (const auto& [pid, traffic] : processTraffic) {
                uint64_t currDown = traffic.downBytes.load();
                uint64_t currUp = traffic.upBytes.load();
                double procDownSpeed = (currDown - lastDown[pid]) / 1024.0 / 1024.0;
                double procUpSpeed = (currUp - lastUp[pid]) / 1024.0 / 1024.0;
                double procTotalDownMB = currDown / 1024.0 / 1024.0;
                double procTotalUpMB = currUp / 1024.0 / 1024.0;
                if (procDownSpeed > 0.01 || procUpSpeed > 0.01) { // 仅显示活跃进程
                    printf("%s (PID: %lu): 下行: %.2f MB/s \t 上行: %.2f MB/s \t 累计下行: %.2f MB \t 累计上行: %.2f MB\n",
                           getProcessName(pid).c_str(), pid, procDownSpeed, procUpSpeed, procTotalDownMB, procTotalUpMB);
                }
                lastDown[pid] = currDown;
                lastUp[pid] = currUp;
            }
        }
        fflush(stdout);

        lastDown[0] = currentDown;
        lastUp[0] = currentUp;
    }
}

int main(int argc, char* argv[]) {
    // 检查管理员权限
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdminSid;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdminSid)) {
        CheckTokenMembership(NULL, AdminSid, &isAdmin);
        FreeSid(AdminSid);
    }
    // if (!isAdmin) {
    //     fprintf(stderr, "错误: 请以管理员身份运行程序\n");
    //     return 1;
    // }

    // 初始化 Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup 失败: %d\n", WSAGetLastError());
        return 1;
    }

    // 获取网卡列表
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "查找网卡失败: %s\n", errbuf);
        WSACleanup();
        return 1;
    }

    // 列出所有网卡
    std::vector<pcap_if_t*> devices;
    for (pcap_if_t* d = alldevs; d; d = d->next) {
        devices.push_back(d);
    }
    if (devices.empty()) {
        fprintf(stderr, "未找到网卡\n");
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 1;
    }

    // 选择网卡
    size_t selected = 0;
    if (argc > 1) {
        try {
            selected = std::stoul(argv[1]);
            if (selected >= devices.size()) {
                fprintf(stderr, "无效的网卡编号: %s\n", argv[1]);
                pcap_freealldevs(alldevs);
                WSACleanup();
                return 1;
            }
        } catch (...) {
            fprintf(stderr, "无效的网卡编号参数: %s\n", argv[1]);
            pcap_freealldevs(alldevs);
            WSACleanup();
            return 1;
        }
    } else {
        printf("可用网卡列表:\n");
        for (size_t i = 0; i < devices.size(); ++i) {
            printf("[%zu] %s - %s\n", i, devices[i]->name, devices[i]->description ? devices[i]->description : "无描述");
        }
        printf("请输入网卡编号 (0-%zu): ", devices.size() - 1);
        std::cin >> selected;
        if (selected >= devices.size()) {
            fprintf(stderr, "无效的网卡编号\n");
            pcap_freealldevs(alldevs);
            WSACleanup();
            return 1;
        }
    }

    pcap_if_t* dev = devices[selected];
    printf("已选择网卡: %s, %s\n", dev->name, dev->description ? dev->description : "无描述");

    // 获取 MAC 和 IP 地址
    if (!getLocalMacAndIp(dev->name, localMac, localIp)) {
        fprintf(stderr, "警告: 无法获取 MAC 地址，将使用 IP 地址区分上下行\n");
    } else {
        printf("MAC 地址: %s, IP 地址: %s\n", localMac.c_str(), localIp.c_str());
    }

    // 打开网卡
    pcap_t* handle = pcap_open_live(dev->name, 262144, 1, 10, errbuf);
    if (!handle) {
        fprintf(stderr, "无法打开网卡: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 1;
    }

    // 设置过滤器，仅捕获 TCP/UDP
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "tcp or udp", 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "设置过滤器失败: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 1;
    }
    pcap_freecode(&fp);

    // 启动连接表更新线程
    std::thread connThread([] {
        while (true) {
            updateConnectionMap();
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    });
    connThread.detach();

    // 启动监控线程
    std::thread monitorThread(MonitorThread);
    monitorThread.detach();

    // 捕获数据包
    printf("按 Ctrl+C 停止监控\n");
    pcap_loop(handle, 0, packetHandler, NULL);

    // 清理
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    WSACleanup();
    return 0;
}