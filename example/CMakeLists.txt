cmake_minimum_required(VERSION 3.1)

set(CMAKE_CXX_STANDARD 11)

#set(CMAKE_BUILD_TYPE Debug)

include_directories(../)

add_executable(HttpUFileServer rttp_asio_file_server.cpp http.cpp)
add_executable(HttpUGetFile rttp_async_file_client.cpp http.cpp)

IF(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set(CMAKE_CXX_FLAGS_RELEASE "/O2")
    target_link_libraries(HttpUFileServer UTPLib  ws2_32.lib)
    target_link_libraries(HttpUGetFile UTPLib  ws2_32.lib)
ELSE(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} "-pthread")
    
    IF(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
        include_directories(/usr/local/include)
        target_link_libraries(HttpUFileServer UTPLib  /usr/local/lib/libboost_system.a /usr/local/lib/libboost_filesystem.a)
        target_link_libraries(HttpUGetFile UTPLib )
    ELSE(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
        target_link_libraries(HttpUFileServer UTPLib  boost_system boost_filesystem)
        target_link_libraries(HttpUGetFile UTPLib )
    ENDIF(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
ENDIF(${CMAKE_SYSTEM_NAME} MATCHES "Windows")

