cmake_minimum_required(VERSION 3.22.1)
project(wafielib C)

set(CMAKE_C_STANDARD 17)
set(MODSECURITY_INCLUDE_DIRS /usr/local/modsecurity/include)
set(MODSECURITY_LIBRARIES /usr/local/modsecurity/lib/libmodsecurity.a)
set(LIBPCRE2_LIBRARIES /usr/lib/aarch64-linux-gnu/libpcre2-8.a)
set(LIBGEOIP_LIBRARIES /usr/lib/aarch64-linux-gnu/libGeoIP.so)
set(LIBYAJL_LIBRARIES /usr/lib/aarch64-linux-gnu/libyajl.so)

find_package(LibXml2 REQUIRED)
find_package(CURL REQUIRED)

include_directories(
        include
        src
        ${MODSECURITY_INCLUDE_DIRS}
)

add_library(wafie SHARED
        src/wafielib.c)

target_link_libraries(wafie PRIVATE
        -Wl,--whole-archive
        ${MODSECURITY_LIBRARIES}
        ${LIBPCRE2_LIBRARIES}
        -Wl,--no-whole-archive
        ${LIBXML2_LIBRARIES}
        ${CURL_LIBRARIES}
        ${LIBGEOIP_LIBRARIES}
        ${LIBYAJL_LIBRARIES}
)

add_executable(test_hello src/test.c)
target_link_libraries(test_hello wafie)