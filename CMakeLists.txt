cmake_minimum_required(VERSION 2.8)
project (adbd)

add_definitions (
    -DADB_HOST_ON_TARGET
	-O2
	-Wall -Wno-unused-parameter -Wno-deprecated-declarations
	-D_GNU_SOURCE -D_XOPEN_SOURCE
)

set(SOURCES
 ${PROJECT_SOURCE_DIR}/adb.c
 
 ${PROJECT_SOURCE_DIR}/fdevent.c
 
 ${PROJECT_SOURCE_DIR}/transport.c
 ${PROJECT_SOURCE_DIR}/transport_local.c
 ${PROJECT_SOURCE_DIR}/transport_usb.c
 
 ${PROJECT_SOURCE_DIR}/sockets.c
 ${PROJECT_SOURCE_DIR}/sockets_libcutils.c
 
 ${PROJECT_SOURCE_DIR}/usb_linux_client.c
 
 ${PROJECT_SOURCE_DIR}/services.c
 ${PROJECT_SOURCE_DIR}/file_sync_service.c
 ${PROJECT_SOURCE_DIR}/priv_service.c
)

#static link
#set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")

include_directories (${PROJECT_SOURCE_DIR}/)

include_directories (${PROJECT_SOURCE_DIR}/include)
add_executable(adbd ${SOURCES})
target_link_libraries(adbd -lpthread)