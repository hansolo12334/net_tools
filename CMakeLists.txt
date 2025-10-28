cmake_minimum_required(VERSION 3.10)
project(NetworkMonitor LANGUAGES CXX)


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 指定 Npcap SDK 路径
set(NPCAP_SDK_DIR "D:/project/net_tools/wpdpack")
set(NPCAP_INCLUDE_DIR "${NPCAP_SDK_DIR}/Include")
set(NPCAP_LIB_DIR "${NPCAP_SDK_DIR}/Lib/x64")


include_directories(${NPCAP_INCLUDE_DIR})
link_directories(${NPCAP_LIB_DIR})


add_executable(network_monitor main1.cpp)


target_link_libraries(network_monitor PRIVATE wpcap ws2_32 iphlpapi)

# 确保以管理员身份运行
set_target_properties(network_monitor PROPERTIES
    VS_DEBUGGER_ENVIRONMENT "PATH=%PATH%;${NPCAP_LIB_DIR}"
)

# 为 MinGW 添加特定设置
if(MINGW)
    add_definitions(-D_WIN32_WINNT=0x0601) # Windows 7 及以上
endif()




include_directories(${CMAKE_SOURCE_DIR}/include)

# 链接库目录
link_directories(${NPCAP_LIB_DIR})

# 添加 DLL
add_library(network_monitor_dll SHARED python_dll.cpp)

# 链接库
target_link_libraries(network_monitor_dll PRIVATE wpcap ws2_32 iphlpapi psapi)


# 设置 DLL 导出
set_target_properties(network_monitor_dll PROPERTIES
    PREFIX ""
    OUTPUT_NAME "network_monitor_dll"
    WINDOWS_EXPORT_ALL_SYMBOLS TRUE
)