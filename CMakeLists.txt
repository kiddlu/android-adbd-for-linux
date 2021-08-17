cmake_minimum_required(VERSION 2.8)
project (adbd)

add_definitions (
    -DADB_HOST_ON_TARGET
	-O2
#	-Wall -Wno-unused-parameter -Wno-deprecated-declarations
	-Wno-all -Wno-incompatible-pointer-types -Wno-deprecated-declarations -Wno-implicit-function-declaration
	-D_GNU_SOURCE -D_XOPEN_SOURCE
)

set(SOURCES
 ${PROJECT_SOURCE_DIR}/adbd/adb.c
 
 ${PROJECT_SOURCE_DIR}/adbd/fdevent.c
 
 ${PROJECT_SOURCE_DIR}/adbd/transport.c
 ${PROJECT_SOURCE_DIR}/adbd/transport_local.c
 ${PROJECT_SOURCE_DIR}/adbd/transport_usb.c
 
 ${PROJECT_SOURCE_DIR}/adbd/sockets.c
 ${PROJECT_SOURCE_DIR}/adbd/sockets_libcutils.c
 
 ${PROJECT_SOURCE_DIR}/adbd/usb_linux_client.c
 
 ${PROJECT_SOURCE_DIR}/adbd/services.c
 ${PROJECT_SOURCE_DIR}/adbd/file_sync_service.c
 ${PROJECT_SOURCE_DIR}/adbd/priv_service.c

 ${PROJECT_SOURCE_DIR}/adbd/propd.c
)

#static link
#set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")

include_directories (${PROJECT_SOURCE_DIR}/adbd/)

add_executable(adbd ${SOURCES})
target_link_libraries(adbd -lpthread)

include(cross.cmake)
