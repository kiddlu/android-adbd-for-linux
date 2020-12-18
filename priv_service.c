#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define  TRACE_TAG  TRACE_PRIV

#include "sysdeps.h"
#include "adb.h"
#include "priv_service.h"

void priv_service_proc(int fd, void *arg)
{
    D("priv service thread started, fd=%d arg=%s\n",fd, (char *)arg);

    writex(fd, arg, strlen(arg));
    free(arg);
    adb_close(fd);

}
