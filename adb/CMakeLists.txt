cmake_minimum_required(VERSION 2.8)
project (adb)

add_definitions (
    -DADB_HOST=1 -DHAVE_FORKEXEC=1 -DHAVE_SYMLINKS -DHAVE_TERMIO_H
	-O2
	-Wall -Wno-unused-parameter -Wno-deprecated-declarations
	-D_GNU_SOURCE -D_XOPEN_SOURCE -DWORKAROUND_BUG6558362
)

set(SOURCES
 ${PROJECT_SOURCE_DIR}/adb.c
 ${PROJECT_SOURCE_DIR}/console.c
 ${PROJECT_SOURCE_DIR}/transport.c
 ${PROJECT_SOURCE_DIR}/transport_local.c
 ${PROJECT_SOURCE_DIR}/transport_usb.c
 ${PROJECT_SOURCE_DIR}/commandline.c
 ${PROJECT_SOURCE_DIR}/fdevent.c
 ${PROJECT_SOURCE_DIR}/adb_client.c
 ${PROJECT_SOURCE_DIR}/sockets.c
 ${PROJECT_SOURCE_DIR}/services.c
 ${PROJECT_SOURCE_DIR}/file_sync_client.c
 ${PROJECT_SOURCE_DIR}/usb_vendors.c
 ${PROJECT_SOURCE_DIR}/usb_linux.c
 ${PROJECT_SOURCE_DIR}/get_my_path_linux.c
 ${PROJECT_SOURCE_DIR}/load_file.c
 ${PROJECT_SOURCE_DIR}/socket_inaddr_any_server.c
 ${PROJECT_SOURCE_DIR}/socket_local_client.c
 ${PROJECT_SOURCE_DIR}/socket_local_server.c
 ${PROJECT_SOURCE_DIR}/socket_loopback_client.c
 ${PROJECT_SOURCE_DIR}/socket_loopback_server.c
 ${PROJECT_SOURCE_DIR}/socket_network_client.c
)

#static link
#set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")

include_directories (${PROJECT_SOURCE_DIR})

add_executable(adb ${SOURCES})
target_link_libraries(adb -lpthread)

include(cross.cmake)
