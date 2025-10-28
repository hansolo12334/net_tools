#include <pcap.h>
#include <winsock2.h>
#include <stdio.h>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <string>
#include <vector>
#include <iphlpapi.h>
#include <iostream>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// 全局变量
std::atomic<uint64_t> downBytes(0);
std::atomic<uint64_t> upBytes(0);
std::mutex printMutex;
std::string localMac;
std::string localIp;

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
        // 规范化 Npcap 设备名称（去掉 \Device\NPF_ 前缀）
        std::string ifaceName = iface;
        if (ifaceName.find("\\Device\\NPF_") == 0)
        {
            ifaceName = ifaceName.substr(12); // 移除 \Device\NPF_
        }

        printf("调试: 规范化后的网卡名称: %s\n", ifaceName.c_str());
        printf("调试: 可用适配器列表:\n");
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter)
        {
            printf("  AdapterName: %s, MAC: %02X:%02X:%02X:%02X:%02X:%02X, IP: %s\n",
                   pAdapter->AdapterName,
                   pAdapter->Address[0], pAdapter->Address[1], pAdapter->Address[2],
                   pAdapter->Address[3], pAdapter->Address[4], pAdapter->Address[5],
                   pAdapter->IpAddressList.IpAddress.String);
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

// 数据包处理回调
void packetHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    // 解析以太网帧
    struct ether_header
    {
        u_char dest[6];
        u_char src[6];
        u_short type;
    } *eth = (ether_header *)pkt_data;

    // 检查是否为 IP 数据包
    if (ntohs(eth->type) == 0x0800)
    {
        // 解析 IP 头部
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

        // 仅处理 TCP/UDP
        if (ip->proto == 6 || ip->proto == 17)
        {
            std::string destMac = "";
            char mac[18];
            sprintf(mac, "%02X:%02X:%02X:%02X:%02X:%02X",
                    eth->dest[0], eth->dest[1], eth->dest[2],
                    eth->dest[3], eth->dest[4], eth->dest[5]);
            destMac = mac;

            if (destMac == localMac)
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

void MonitorThread()
{
    uint64_t lastDown = 0, lastUp = 0;
    while (true)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        uint64_t currentDown = downBytes.load();
        uint64_t currentUp = upBytes.load();
        double downSpeed = (currentDown - lastDown) / 1024.0 / 1024.0; // MB/s
        double upSpeed = (currentUp - lastUp) / 1024.0 / 1024.0;       // MB/s
        double totalDownMB = currentDown / 1024.0 / 1024.0;
        double totalUpMB = currentUp / 1024.0 / 1024.0;

        std::lock_guard<std::mutex> lock(printMutex);
        printf("\r下行: %.2f MB/s \t 上行: %.2f MB/s \t 累计下行: %.2f MB \t 累计上行: %.2f MB", downSpeed, upSpeed, totalDownMB, totalUpMB);
        fflush(stdout);

        lastDown = currentDown;
        lastUp = currentUp;
    }
}

int main()
{
    // 检查管理员权限
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdminSid;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdminSid))
    {
        CheckTokenMembership(NULL, AdminSid, &isAdmin);
        FreeSid(AdminSid);
    }
    // if (!isAdmin)
    // {
    //     fprintf(stderr, "错误: 请以管理员身份运行程序\n");
    //     return 1;
    // }

    // 初始化 Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        fprintf(stderr, "WSAStartup 失败: %d\n", WSAGetLastError());
        return 1;
    }

    // 获取网卡列表
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "查找网卡失败: %s\n", errbuf);
        WSACleanup();
        return 1;
    }
    std::vector<pcap_if_t *> devices;
    for (pcap_if_t *d = alldevs; d; d = d->next)
    {
        devices.push_back(d);
    }

    printf("可用网卡列表:\n");
    for (size_t i = 0; i < devices.size(); ++i)
    {
        printf("[%zu] %s - %s\n", i, devices[i]->name, devices[i]->description ? devices[i]->description : "无描述");
    }
    // 选择第一个网卡（可修改为指定网卡）
    // 用户选择网卡
    size_t selected;
    printf("请输入网卡编号 (0-%zu): ", devices.size() - 1);
    std::cin >> selected;
    if (selected >= devices.size())
    {
        fprintf(stderr, "无效的网卡编号\n");
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 1;
    }

    pcap_if_t *dev = devices[selected];
    printf("已选择网卡: %s, %s\n", dev->name, dev->description ? dev->description : "无描述");

    // 获取 MAC 和 IP 地址
    if (!getLocalMacAndIp(dev->name, localMac, localIp))
    {
        fprintf(stderr, "警告: 无法获取 MAC 地址，将使用 IP 地址区分上下行\n");
        // 继续运行，依赖 IP 地址
    }
    else
    {
        printf("MAC 地址: %s, IP 地址: %s\n", localMac.c_str(), localIp.c_str());
    }

    // 获取 MAC 地址
    // localMac = getLocalMac(dev->name);
    // if (localMac.empty())
    // {
    //     fprintf(stderr, "无法获取 MAC 地址\n");
    //     pcap_freealldevs(alldevs);
    //     WSACleanup();
    //     return 1;
    // }
    printf("网卡: %s, MAC: %s\n", dev->name, localMac.c_str());

    // 打开网卡
    pcap_t *handle = pcap_open_live(dev->name, 65536, 1, 10, errbuf);
    if (!handle)
    {
        fprintf(stderr, "无法打开网卡: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 1;
    }

    // 设置过滤器，仅捕获 TCP/UDP
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "tcp or udp", 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "设置过滤器失败: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 1;
    }
    pcap_freecode(&fp);

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