cmake_minimum_required(VERSION 3.22.1)
project(wafielib C)

function(SET_TARGET_ARCH_LIBS)
    if(TARGET_ARCH MATCHES "x86_64" OR TARGET_ARCH MATCHES "amd64")
        set(TARGET_ARCH_LIBS "/usr/lib/x86_64-linux-gnu" PARENT_SCOPE)
    else()
        set(TARGET_ARCH_LIBS "/usr/lib/aarch64-linux-gnu" PARENT_SCOPE)
    endif ()
endfunction()

string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" TARGET_ARCH)
set(CMAKE_C_STANDARD 17)
set(MODSECURITY_INCLUDE_DIRS /usr/local/modsecurity/include)
set(MODSECURITY_LIBRARIES /usr/local/modsecurity/lib/libmodsecurity.a)
set_target_arch_libs()
message(STATUS "TARGET_ARCH_LIBS: ${TARGET_ARCH_LIBS}")

set(LIBPCRE2_LIBRARIES "${TARGET_ARCH_LIBS}/libpcre2-8.a")
set(LIBGEOIP_LIBRARIES "${TARGET_ARCH_LIBS}/libGeoIP.so")
set(LIBYAJL_LIBRARIES "${TARGET_ARCH_LIBS}/libyajl.so")

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
