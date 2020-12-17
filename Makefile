# Makefile for adbd

#arch
SRCS+= adb.c

#fd-event
SRCS+= fdevent.c

#transport layer
SRCS+= transport.c
SRCS+= transport_local.c
SRCS+= transport_usb.c

#net driver
SRCS+= sockets.c
SRCS+= sockets_libcutils.c
#SRCS+= socket_inaddr_any_server.c
#SRCS+= socket_local_client.c
#SRCS+= socket_local_server.c
#SRCS+= socket_loopback_client.c
#SRCS+= socket_loopback_server.c

#usb driver
SRCS+= usb_linux_client.c

#servive
#focus on shell & file sync/pull/push service
SRCS+= services.c
SRCS+= file_sync_service.c
SRCS+= priv_service.c

CFLAGS+= -DADB_HOST=0
CFLAGS+= -DANDROID_SMP=1
CFLAGS+= -DHAVE_SYS_SOCKET_H
CFLAGS+= -DHAVE_PTHREADS
CFLAGS+= -D_GNU_SOURCE
CFLAGS+= -D_XOPEN_SOURCE
CFLAGS+= -I$(shell pwd)
#LDFLAGS= -static 
LIBS= -lpthread

TOOLCHAIN=
CC= $(TOOLCHAIN)gcc

OBJS= $(SRCS:%.c=%.o)
#OBJS+= $(S_SRCS:%.S=%.o)

all: adbd

adbd: $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS) $(LIBS)

clean:
	rm -rf adb $(OBJS)
