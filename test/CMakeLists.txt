cmake_minimum_required(VERSION 3.24)
project(dnsTunTest)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_BUILD_TYPE Debug)

# 包含头文件目录
include_directories(${CMAKE_SOURCE_DIR}/../include)

# 添加测试可执行文件
add_executable(dnsTunTest test_main.cpp test2.cpp)

# 链接静态库
target_link_libraries(dnsTunTest dnsTun)

if(WIN32)
    target_link_libraries(dnsTun PRIVATE ws2_32)
else()
    # 查找Threads库
    find_package(Threads REQUIRED)
    # 链接Threads库
    target_link_libraries(dnsTun ${CMAKE_THREAD_LIBS_INIT})
endif()
