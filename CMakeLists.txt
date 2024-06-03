cmake_minimum_required(VERSION 3.24)
project(dnsTun)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_BUILD_TYPE Debug)
include_directories(include)
file(GLOB SOURCES "src/*/*.cpp" "src/*/*.h" "src/*/*.hpp")

add_library(dnsTun STATIC ${SOURCES} )

# 添加测试可执行文件
add_executable(dnsTunTest test/test_main.cpp test/EchoServer.hpp test/EchoClient.hpp test/TimeServer.hpp test/DiscardClient.h)

# 链接静态库到测试可执行文件
target_link_libraries(dnsTunTest dnsTun)

target_include_directories(dnsTun PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(WIN32)
    target_link_libraries(dnsTun PRIVATE ws2_32)
else()
    # 查找Threads库
    find_package(Threads REQUIRED)
    # 链接Threads库
    target_link_libraries(dnsTun ${CMAKE_THREAD_LIBS_INIT})
endif()
