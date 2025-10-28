#include <pcap.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <stdio.h>
#include <thread>
#include <mutex>
#include <atomic>
#include <string>
#include <vector>
#include <map>
#include <nlohmann/json.hpp>
#include <psapi.h>
#include <iostream>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

// 使用 nlohmann/json
using json = nlohmann::json;

// 全局变量
std::atomic<uint64_t> downBytes(0);
std::atomic<uint64_t> upBytes(0);
std::atomic<uint64_t> downPackets(0); // 下行包数
std::atomic<uint64_t> upPackets(0);   // 上行包数

std::mutex printMutex;
std::string localMac;
std::string localIp;
std::atomic<bool> running(false);
pcap_t *handle = nullptr;
std::thread captureThread;
std::thread connThread;

// 进程流量统计
struct ProcessTraffic
{
    std::atomic<uint64_t> downBytes{0};
    std::atomic<uint64_t> upBytes{0};

    std::atomic<uint64_t> downBytes_ipv4{0};
    std::atomic<uint64_t> upBytes_ipv4{0};
    std::atomic<uint64_t> downBytes_ipv6{0};
    std::atomic<uint64_t> upBytes_ipv6{0};

    std::atomic<uint64_t> downPackets{0}; // 下行包数
    std::atomic<uint64_t> upPackets{0};   // 上行包数
};
std::map<DWORD, ProcessTraffic> processTraffic;
std::mutex processTrafficMutex;

// 连接信息
struct ConnectionKey
{
    std::string localIp;
    uint16_t localPort;
    std::string remoteIp;
    uint16_t remotePort;
    bool operator<(const ConnectionKey &other) const
    {
        return std::tie(localIp, localPort, remoteIp, remotePort) <
               std::tie(other.localIp, other.localPort, other.remoteIp, other.remotePort);
    }
};

std::map<ConnectionKey, DWORD> connectionMap;
std::mutex connectionMapMutex;
std::vector<pcap_if_t *> devices;
pcap_if_t *alldevs;

// 获取进程名称
std::string getProcessName(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess)
        return "Unknown";
    char name[MAX_PATH] = {0};
    GetProcessImageFileNameA(hProcess, name, MAX_PATH);
    CloseHandle(hProcess);
    std::string result = name;
    size_t pos = result.find_last_of("\\");

    return pos != std::string::npos ? result.substr(pos + 1) : result;
}

// 获取本地 IPv4/IPv6 地址
std::string getLocalIp(const char *iface)
{
    PIP_ADAPTER_ADDRESSES pAddresses = nullptr;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_ADDRESSES);
    pAddresses = (IP_ADAPTER_ADDRESSES *)malloc(ulOutBufLen);
    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
    {
        free(pAddresses);
        pAddresses = (IP_ADAPTER_ADDRESSES *)malloc(ulOutBufLen);
    }
    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &ulOutBufLen) == NO_ERROR)
    {
        PIP_ADAPTER_ADDRESSES pAdapter = pAddresses;
        while (pAdapter)
        {
            if (std::string(pAdapter->AdapterName).find(iface) != std::string::npos)
            {
                PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pAdapter->FirstUnicastAddress;
                while (pUnicast)
                {
                    char ip[INET_ADDRSTRLEN];
                    if (pUnicast->Address.lpSockaddr->sa_family == AF_INET)
                    {
                        inet_ntop(AF_INET, &((struct sockaddr_in *)pUnicast->Address.lpSockaddr)->sin_addr, ip, sizeof(ip));
                        free(pAddresses);
                        return std::string(ip);
                    }
                    pUnicast = pUnicast->Next;
                }
            }
            pAdapter = pAdapter->Next;
        }
    }
    free(pAddresses);
    return "";
}

// 获取本地 MAC 地址
std::string getLocalMac(const char *iface)
{
    PIP_ADAPTER_INFO pAdapterInfo;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
    {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
    }
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR)
    {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter)
        {
            if (std::string(pAdapter->AdapterName).find(iface) != std::string::npos)
            {
                char mac[18];
                sprintf(mac, "%02X:%02X:%02X:%02X:%02X:%02X",
                        pAdapter->Address[0], pAdapter->Address[1], pAdapter->Address[2],
                        pAdapter->Address[3], pAdapter->Address[4], pAdapter->Address[5]);
                free(pAdapterInfo);
                return std::string(mac);
            }
            pAdapter = pAdapter->Next;
        }
    }
    free(pAdapterInfo);
    return "";
}
// 获取本地 MAC 和 IP 地址
bool getLocalMacAndIp(const char *iface, std::string &mac, std::string &ip)
{
    PIP_ADAPTER_INFO pAdapterInfo;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
    {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
    }

    bool found = false;
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR)
    {
        std::string ifaceName = iface;
        if (ifaceName.find("\\Device\\NPF_") == 0)
        {
            ifaceName = ifaceName.substr(12);
        }

        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter)
        {
            if (std::string(pAdapter->AdapterName) == ifaceName)
            {
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
void updateConnectionMap()
{
    // 获取 IPV4 TCP 连接（带 PID）
    PMIB_TCPTABLE2 pTcpTable = nullptr;
    ULONG ulSize = 0;
    if (GetTcpTable2(nullptr, &ulSize, FALSE) == ERROR_INSUFFICIENT_BUFFER)
    {
        pTcpTable = (PMIB_TCPTABLE2)malloc(ulSize);
        if (GetTcpTable2(pTcpTable, &ulSize, FALSE) == NO_ERROR)
        {
            std::lock_guard<std::mutex> lock(connectionMapMutex);
            connectionMap.clear();
            for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++)
            {
                auto &row = pTcpTable->table[i];
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

    // 获取IPV4 UDP 连接（带 PID）
    PMIB_UDPTABLE_OWNER_PID pUdpTable = nullptr;
    ulSize = 0;
    if (GetExtendedUdpTable(nullptr, &ulSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == ERROR_INSUFFICIENT_BUFFER)
    {
        pUdpTable = (PMIB_UDPTABLE_OWNER_PID)malloc(ulSize);
        if (GetExtendedUdpTable(pUdpTable, &ulSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR)
        {
            std::lock_guard<std::mutex> lock(connectionMapMutex);
            for (DWORD i = 0; i < pUdpTable->dwNumEntries; i++)
            {
                auto &row = pUdpTable->table[i];
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

    // IPv6 TCP
    PMIB_TCP6TABLE_OWNER_PID pTcp6Table = nullptr;
    ulSize = 0;
    if (GetExtendedTcpTable(nullptr, &ulSize, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
        pTcp6Table = (PMIB_TCP6TABLE_OWNER_PID)malloc(ulSize);
        if (GetExtendedTcpTable(pTcp6Table, &ulSize, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            std::lock_guard<std::mutex> lock(connectionMapMutex);
            for (DWORD i = 0; i < pTcp6Table->dwNumEntries; i++) {
                auto &row = pTcp6Table->table[i];
                ConnectionKey key;
                char localIp[INET6_ADDRSTRLEN], remoteIp[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &row.ucLocalAddr, localIp, sizeof(localIp));
                inet_ntop(AF_INET6, &row.ucRemoteAddr, remoteIp, sizeof(remoteIp));
                key.localIp = localIp;
                key.localPort = ntohs((uint16_t)row.dwLocalPort);
                key.remoteIp = remoteIp;
                key.remotePort = ntohs((uint16_t)row.dwRemotePort);
                connectionMap[key] = row.dwOwningPid;
                // printf("IPv6 TCP Connection: %s:%d -> %s:%d, PID: %lu\n",
                //        key.localIp.c_str(), key.localPort, key.remoteIp.c_str(), key.remotePort, row.dwOwningPid);
            }
        } else {
            printf("GetExtendedTcpTable IPv6 失败: %lu\n", GetLastError());
        }
        free(pTcp6Table);
    }

    // IPv6 UDP
    PMIB_UDP6TABLE_OWNER_PID pUdp6Table = nullptr;
    ulSize = 0;
    if (GetExtendedUdpTable(nullptr, &ulSize, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == ERROR_INSUFFICIENT_BUFFER) {
        pUdp6Table = (PMIB_UDP6TABLE_OWNER_PID)malloc(ulSize);
        if (GetExtendedUdpTable(pUdp6Table, &ulSize, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            std::lock_guard<std::mutex> lock(connectionMapMutex);
            for (DWORD i = 0; i < pUdp6Table->dwNumEntries; i++) {
                auto &row = pUdp6Table->table[i];
                ConnectionKey key;
                char localIp[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &row.ucLocalAddr, localIp, sizeof(localIp));
                key.localIp = localIp;
                key.localPort = ntohs((uint16_t)row.dwLocalPort);
                key.remoteIp = "::";
                key.remotePort = 0;
                connectionMap[key] = row.dwOwningPid;
                // printf("IPv6 UDP Connection: %s:%d -> %s:%d, PID: %lu\n",
                //        key.localIp.c_str(), key.localPort, key.remoteIp.c_str(), key.remotePort, row.dwOwningPid);
            }
        } else {
            printf("GetExtendedUdpTable IPv6 失败: %lu\n", GetLastError());
        }
        free(pUdp6Table);
    }
    // printf("更新连接表，条目数: %zu\n", connectionMap.size());
}

// 数据包处理回调

void packetHandler1(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{

    struct ether_header
    {
        u_char dest[6];
        u_char src[6];
        u_short type;
    } *eth = (ether_header *)pkt_data;
    if (ntohs(eth->type) == 0x0800 || ntohs(eth->type) == 0x86DD)
    { // IPv4 或 IPv6
        bool isIPv6 = (ntohs(eth->type) == 0x86DD);
        bool isDownlink = false;
        std::string destMac;
        char mac[18];
        sprintf(mac, "%02X:%02X:%02X:%02X:%02X:%02X",
                eth->dest[0], eth->dest[1], eth->dest[2],
                eth->dest[3], eth->dest[4], eth->dest[5]);

        destMac = mac;
        isDownlink = (destMac == localMac);

        if (isIPv6)
        {
            struct ipv6_header
            {
                u_char ver_tc_fl[4];
                u_short payload_len;
                u_char next_hdr;
                u_char hop_limit;
                u_char src[16];
                u_char dst[16];
            } *ip6 = (ipv6_header *)(pkt_data + 14);

            if (ip6->next_hdr == 6 || ip6->next_hdr == 17)
            { // TCP 或 UDP
                struct tcp_udp_header
                {
                    u_short src_port;
                    u_short dst_port;
                } *transport = (tcp_udp_header *)(pkt_data + 14 + 40); // IPv6 头部固定 40 字节

                ConnectionKey key;

                char srcIp[INET6_ADDRSTRLEN], dstIp[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, ip6->src, srcIp, sizeof(srcIp));
                inet_ntop(AF_INET6, ip6->dst, dstIp, sizeof(dstIp));
                // if (!isDownlink)
                // {
                //     char tmp[INET6_ADDRSTRLEN];
                //     strcpy(tmp, srcIp);
                //     strcpy(srcIp, dstIp);
                //     strcpy(dstIp, tmp);
                // }
                key.localIp = isDownlink ? dstIp : srcIp;
                key.localPort = ntohs(isDownlink ? transport->dst_port : transport->src_port);
                key.remoteIp = isDownlink ? srcIp : dstIp;
                key.remotePort = ntohs(isDownlink ? transport->src_port : transport->dst_port);

                DWORD pid = 0;
                {
                    std::lock_guard<std::mutex> lock(connectionMapMutex);
                    auto it = connectionMap.find(key);
                    if (it != connectionMap.end())
                    {
                        pid = it->second;
                    }
                    else if (ip6->next_hdr == 17)
                    {
                        key.remoteIp = "::";
                        key.remotePort = 0;
                        it = connectionMap.find(key);
                        if (it != connectionMap.end())
                        {
                            pid = it->second;
                        }
                    }
                }

                if (pid != 0)
                {
                    std::lock_guard<std::mutex> lock(processTrafficMutex);
                    if (isDownlink)
                    {
                        processTraffic[pid].downBytes_ipv6 += header->len;
                        processTraffic[pid].downPackets += 1;
                        // printf("Process %lu IPv6 Down: %llu bytes\n", pid, processTraffic[pid].downBytes_ipv6.load());
                    }
                    else
                    {
                        // printf("ipv6上传");
                        processTraffic[pid].upBytes_ipv6 += header->len;
                        processTraffic[pid].upPackets += 1;
                        // printf("Process %lu IPv6 Up: %llu bytes\n", pid, processTraffic[pid].upBytes_ipv6.load());
                    }
                }

                if (isDownlink)
                {
                    downBytes += header->len;
                    downPackets += 1;
                }
                else
                {
                    upBytes += header->len;
                    upPackets += 1;
                }
            }
        }
        else
        {
            struct ip_header
            {
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
            } *ip = (ip_header *)(pkt_data + 14);

            if (ip->proto == 6 || ip->proto == 17)
            {
                struct tcp_udp_header
                {
                    u_short src_port;
                    u_short dst_port;
                } *transport = (tcp_udp_header *)(pkt_data + 14 + ((ip->ver_ihl & 0x0F) * 4));

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
                    if (it != connectionMap.end())
                    {
                        pid = it->second;
                    }
                    else if (ip->proto == 17)
                    {
                        key.remoteIp = "0.0.0.0";
                        key.remotePort = 0;
                        it = connectionMap.find(key);
                        if (it != connectionMap.end())
                        {
                            pid = it->second;
                        }
                    }
                }

                if (pid != 0)
                {
                    std::lock_guard<std::mutex> lock(processTrafficMutex);
                    if (isDownlink)
                    {
                        processTraffic[pid].downBytes_ipv4 += header->len;
                        processTraffic[pid].downPackets += 1;
                        // printf("Process %lu IPv4 Down: %llu bytes\n", pid, processTraffic[pid].downBytes_ipv4.load());
                    }
                    else
                    {
                        processTraffic[pid].upBytes_ipv4 += header->len;
                        processTraffic[pid].upPackets += 1;
                    }
                }

                if (isDownlink)
                {
                    downBytes += header->len;
                    downPackets += 1;
                }
                else
                {
                    upBytes += header->len;
                    upPackets += 1;
                }
            }
        }
    }
}

void packetHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct ether_header
    {
        u_char dest[6];
        u_char src[6];
        u_short type;
    } *eth = (ether_header *)pkt_data;

    if (ntohs(eth->type) == 0x0800)
    {
        struct ip_header
        {
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
        } *ip = (ip_header *)(pkt_data + 14);

        if (ip->proto == 6 || ip->proto == 17)
        {
            struct tcp_udp_header
            {
                u_short src_port;
                u_short dst_port;
            } *transport = (tcp_udp_header *)(pkt_data + 14 + ((ip->ver_ihl & 0x0F) * 4));

            bool isDownlink = false;
            if (!localMac.empty())
            {
                std::string destMac;
                char mac[18];
                sprintf(mac, "%02X:%02X:%02X:%02X:%02X:%02X",
                        eth->dest[0], eth->dest[1], eth->dest[2],
                        eth->dest[3], eth->dest[4], eth->dest[5]);
                destMac = mac;
                isDownlink = (destMac == localMac);
            }
            else
            {
                char dstIp[16];
                sprintf(dstIp, "%d.%d.%d.%d", ip->dst[0], ip->dst[1], ip->dst[2], ip->dst[3]);
                isDownlink = (std::string(dstIp) == localIp);
            }

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
                if (it != connectionMap.end())
                {
                    pid = it->second;
                }
                else if (ip->proto == 17)
                {
                    key.remoteIp = "0.0.0.0";
                    key.remotePort = 0;
                    it = connectionMap.find(key);
                    if (it != connectionMap.end())
                    {
                        pid = it->second;
                    }
                }
            }

            if (pid != 0)
            {
                std::lock_guard<std::mutex> lock(processTrafficMutex);
                if (isDownlink)
                {
                    processTraffic[pid].downBytes += header->len;
                    processTraffic[pid].downPackets += 1;
                }
                else
                {
                    processTraffic[pid].upBytes += header->len;
                    processTraffic[pid].upPackets += 1;
                }
            }

            if (isDownlink)
            {
                downBytes += header->len;
            }
            else
            {
                upBytes += header->len;
            }
        }
    }
}

// DLL 接口
extern "C"
{
    EXPORT const char *start_monitor(int adapter_index)
    {
        if (running)
        {
            return "{\"error\": \"Monitor already running\"}";
        }

        // 检查管理员权限
        BOOL isAdmin = FALSE;
        SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
        PSID AdminSid;
        if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                     DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdminSid))
        {
            CheckTokenMembership(NULL, AdminSid, &isAdmin);
            FreeSid(AdminSid);
        }
        // if (!isAdmin) {
        //     return "{\"error\": \"Administrator privileges required\"}";
        // }

        // 初始化 Winsock
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        {
            return "{\"error\": \"WSAStartup failed\"}";
        }

        // 获取网卡列表

        char errbuf[PCAP_ERRBUF_SIZE];
        if (pcap_findalldevs(&alldevs, errbuf) == -1)
        {
            WSACleanup();
            return "{\"error\": \"Failed to find adapters\"}";
        }

        // 列出所有网卡
        for (pcap_if_t *d = alldevs; d; d = d->next)
        {
            devices.push_back(d);
        }

        if (adapter_index < 0 || static_cast<size_t>(adapter_index) >= devices.size())
        {
            pcap_freealldevs(alldevs);
            devices.clear();
            WSACleanup();
            return "{\"error\": \"Invalid adapter index\"}";
        }

        pcap_if_t *dev = devices[adapter_index];
        if (!getLocalMacAndIp(dev->name, localMac, localIp))
        {
            fprintf(stderr, "警告: 无法获取 MAC 地址，将使用 IP 地址\n");
        }

        // 打开网卡
        handle = pcap_open_live(dev->name, 262144, 1, 10, errbuf);
        if (!handle)
        {
            pcap_freealldevs(alldevs);
            devices.clear();
            WSACleanup();
            return "{\"error\": \"Failed to open adapter\"}";
        }

        // 设置过滤器
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, "tcp or udp", 0, PCAP_NETMASK_UNKNOWN) == -1 ||
            pcap_setfilter(handle, &fp) == -1)
        {
            pcap_close(handle);
            pcap_freealldevs(alldevs);
            devices.clear();
            WSACleanup();
            return "{\"error\": \"Failed to set filter\"}";
        }
        pcap_freecode(&fp);

        // 启动线程
        running = true;
        connThread = std::thread([]
                                 {
            while (running) {
                updateConnectionMap();
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            } });
        connThread.detach();

        captureThread = std::thread([]
                                    { pcap_loop(handle, 0, packetHandler1, nullptr); });
        captureThread.detach();

        json result = {
            {"success", true},
            {"adapter", dev->name},
            {"description", dev->description ? dev->description : "No description"},
            {"mac", localMac},
            {"ip", localIp}};

        return strdup(result.dump().c_str());
    }

    EXPORT void stop_monitor()
    {
        if (running)
        {
            running = false;
            if (handle)
            {
                pcap_breakloop(handle);
                pcap_close(handle);
                handle = nullptr;
            }
            pcap_freealldevs(alldevs);
            devices.clear();
            WSACleanup();
            {
                std::lock_guard<std::mutex> lock(processTrafficMutex);
                processTraffic.clear();
            }
            {
                std::lock_guard<std::mutex> lock(connectionMapMutex);
                connectionMap.clear();
            }
            downBytes = 0;
            upBytes = 0;
        }
    }

    EXPORT const char *get_processes()
    {
        json result = json::array();
        std::lock_guard<std::mutex> lock(processTrafficMutex);
        for (const auto &[pid, traffic] : processTraffic)
        {
            if (traffic.downBytes_ipv4 > 0 || traffic.upBytes_ipv6 > 0 ||
                traffic.downBytes_ipv6 > 0 || traffic.upBytes_ipv4 > 0)
            {
                // if(traffic.downBytes_ipv6 > 0){
                //     printf("Process %lu IPv6 Down: %llu bytes\n", pid, traffic.downBytes_ipv6.load());
                // }
                auto name = getProcessName(pid);
                result.push_back({{"pid", pid},
                                  {"name", name}});
            }
        }
        return strdup(result.dump().c_str());
    }

    EXPORT const char *get_process_traffic(DWORD pid)
    {
        static std::map<DWORD, uint64_t> lastDown, lastUp;
        json result;
        std::lock_guard<std::mutex> lock(processTrafficMutex);
        auto it = processTraffic.find(pid);

        if (it != processTraffic.end())
        {
            uint64_t currDown = it->second.downBytes_ipv4.load() + it->second.downBytes_ipv6.load();
            uint64_t currUp = it->second.upBytes_ipv4.load() + it->second.upBytes_ipv6.load();
            double downSpeed = (currDown - lastDown[pid]) / 1024.0 / 1024.0;
            double upSpeed = (currUp - lastUp[pid]) / 1024.0 / 1024.0;
            double totalDownMB = currDown / 1024.0 / 1024.0;
            double totalUpMB = currUp / 1024.0 / 1024.0;

            double downPackets = it->second.downPackets.load();
            double upPackets = it->second.upPackets.load();

            lastDown[pid] = currDown;
            lastUp[pid] = currUp;
            result = {
                {"pid", pid},
                {"name", getProcessName(pid)},
                {"down_speed_mbs", downSpeed},
                {"up_speed_mbs", upSpeed},
                {"total_down_mb", totalDownMB},
                {"total_up_mb", totalUpMB},
                {"down_packets", downPackets},
                {"up_packets", upPackets},
                {"down_bytes_ipv4", it->second.downBytes_ipv4.load() / 1024.0 / 1024.0},
                {"up_bytes_ipv4", it->second.upBytes_ipv4.load() / 1024.0 / 1024.0},
                {"down_bytes_ipv6", it->second.downBytes_ipv6.load() / 1024.0 / 1024.0},
                {"up_bytes_ipv6", it->second.upBytes_ipv6.load() / 1024.0 / 1024.0}};
        }
        else
        {
            // std::cout<<"Process not found"<<'\n';
            result = {"error", "Process not found"};
        }
        return strdup(result.dump().c_str());
    }

    EXPORT const char *get_total_traffic()
    {
        static uint64_t lastDown = 0, lastUp = 0;
        uint64_t currDown = downBytes.load();
        uint64_t currUp = upBytes.load();
        double downSpeed = (currDown - lastDown) / 1024.0 / 1024.0;
        double upSpeed = (currUp - lastUp) / 1024.0 / 1024.0;
        double totalDownMB = currDown / 1024.0 / 1024.0;
        double totalUpMB = currUp / 1024.0 / 1024.0;
        lastDown = currDown;
        lastUp = currUp;
        json result = {
            {"down_speed_mbs", downSpeed},
            {"up_speed_mbs", upSpeed},
            {"total_down_mb", totalDownMB},
            {"total_up_mb", totalUpMB}};
        return strdup(result.dump().c_str());
    }
}