/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define  TRACE_TAG   TRACE_ADB

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <stdint.h>

#include "sysdeps.h"
#include "adb.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#define PROP_VALUE_MAX  92
#define PROPERTY_VALUE_MAX  PROP_VALUE_MAX
#include "sockets_libcutils.h"
#include <linux/capability.h>
#include <linux/prctl.h>
#include <sys/mount.h>

#if ADB_TRACE
ADB_MUTEX_DEFINE( D_lock );
#endif

int HOST = 0;
int SIMPLE_AUTH = 0;

int gListenAll = 0;

static int auth_enabled = 0;

static const char *adb_device_banner = "device";

#define MAX_LOG_STRING 2048

void adb_log_print(const char *file, int line_n, const char *function, const char *format, ...)
{
	va_list list;

	char log_line[MAX_LOG_STRING];
	int prefix_length = -1;

	/* Creating the full log prefix */
	prefix_length = snprintf(log_line, MAX_LOG_STRING, "%s:%d:", 
			file, 
			line_n);

	/* Setting pointer where the actual message should start */

	/* Filling out rest of the log message */
	va_start(list, format);
	vsnprintf(log_line + prefix_length, MAX_LOG_STRING - prefix_length, format, list);
	va_end(list);

	printf("%s", log_line);
}


void fatal(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(-1);
}

void fatal_errno(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "error: %s: ", strerror(errno));
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(-1);
}

int   adb_trace_mask;

/* read a comma/space/colum/semi-column separated list of tags
 * from the ADB_TRACE environment variable and build the trace
 * mask from it. note that '1' and 'all' are special cases to
 * enable all tracing
 */
void  adb_trace_init(void)
{
    const char*  p = getenv("ADB_TRACE");
    const char*  q;

    static const struct {
        const char*  tag;
        int           flag;
    } tags[] = {
        { "1", 0 },
        { "all", 0 },
        { "adb", TRACE_ADB },
        { "sockets", TRACE_SOCKETS },
        { "packets", TRACE_PACKETS },
        { "rwx", TRACE_RWX },
        { "usb", TRACE_USB },
        { "sync", TRACE_SYNC },
        { "sysdeps", TRACE_SYSDEPS },
        { "transport", TRACE_TRANSPORT },
        { "jdwp", TRACE_JDWP },
        { "services", TRACE_SERVICES },
        { "auth", TRACE_AUTH },
        { NULL, 0 }
    };

    if (p == NULL)
            return;

    /* use a comma/column/semi-colum/space separated list */
    while (*p) {
        int  len, tagn;

        q = strpbrk(p, " ,:;");
        if (q == NULL) {
            q = p + strlen(p);
        }
        len = q - p;

        for (tagn = 0; tags[tagn].tag != NULL; tagn++)
        {
            int  taglen = strlen(tags[tagn].tag);

            if (len == taglen && !memcmp(tags[tagn].tag, p, len) )
            {
                int  flag = tags[tagn].flag;
                if (flag == 0) {
                    adb_trace_mask = ~0;
                    return;
                }
                adb_trace_mask |= (1 << flag);
                break;
            }
        }
        p = q;
        if (*p)
            p++;
    }
}

apacket *get_apacket(void)
{
    apacket *p = malloc(sizeof(apacket));
    if(p == 0) fatal("failed to allocate an apacket");
    memset(p, 0, sizeof(apacket) - MAX_PAYLOAD);
    return p;
}

void put_apacket(apacket *p)
{
    free(p);
}

void handle_online(atransport *t)
{
    D("adb: online\n");
    t->online = 1;
}

void handle_offline(atransport *t)
{
    D("adb: offline\n");
    //Close the associated usb
    t->online = 0;
    run_transport_disconnects(t);
}

#if DEBUG_PACKETS
#define DUMPMAX 32
void print_packet(const char *label, apacket *p)
{
    char *tag;
    char *x;
    unsigned count;

    switch(p->msg.command){
    case A_SYNC: tag = "SYNC"; break;
    case A_CNXN: tag = "CNXN" ; break;
    case A_OPEN: tag = "OPEN"; break;
    case A_OKAY: tag = "OKAY"; break;
    case A_CLSE: tag = "CLSE"; break;
    case A_WRTE: tag = "WRTE"; break;
    case A_AUTH: tag = "AUTH"; break;
    default: tag = "????"; break;
    }

    fprintf(stderr, "%s: %s %08x %08x %04x \"",
            label, tag, p->msg.arg0, p->msg.arg1, p->msg.data_length);
    count = p->msg.data_length;
    x = (char*) p->data;
    if(count > DUMPMAX) {
        count = DUMPMAX;
        tag = "\n";
    } else {
        tag = "\"\n";
    }
    while(count-- > 0){
        if((*x >= ' ') && (*x < 127)) {
            fputc(*x, stderr);
        } else {
            fputc('.', stderr);
        }
        x++;
    }
    fputs(tag, stderr);
}
#endif

static void send_ready(unsigned local, unsigned remote, atransport *t)
{
    D("Calling send_ready \n");
    apacket *p = get_apacket();
    p->msg.command = A_OKAY;
    p->msg.arg0 = local;
    p->msg.arg1 = remote;
    send_packet(p, t);
}

static void send_close(unsigned local, unsigned remote, atransport *t)
{
    D("Calling send_close \n");
    apacket *p = get_apacket();
    p->msg.command = A_CLSE;
    p->msg.arg0 = local;
    p->msg.arg1 = remote;
    send_packet(p, t);
}

static size_t fill_connect_data(char *buf, size_t bufsize)
{
    static const char *cnxn_props[] = {
        "ro.product.name",
        "ro.product.model",
        "ro.product.device",
    };
    static const int num_cnxn_props = ARRAY_SIZE(cnxn_props);
    int i;
    size_t remaining = bufsize;
    size_t len;

    len = snprintf(buf, remaining, "%s::", adb_device_banner);
    remaining -= len;
    buf += len;
    for (i = 0; i < num_cnxn_props; i++) {
        char value[PROPERTY_VALUE_MAX];
        //property_get(cnxn_props[i], value, "");
        len = snprintf(buf, remaining, "%s=%s;", cnxn_props[i], value);
        remaining -= len;
        buf += len;
    }

    return bufsize - remaining + 1;
}

static void send_connect(atransport *t)
{
    D("Calling send_connect \n");
    apacket *cp = get_apacket();
    cp->msg.command = A_CNXN;
    cp->msg.arg0 = A_VERSION;
    cp->msg.arg1 = MAX_PAYLOAD;
    cp->msg.data_length = fill_connect_data((char *)cp->data,
                                            sizeof(cp->data));
    send_packet(cp, t);
}
 

/* qual_overwrite is used to overwrite a qualifier string.  dst is a
 * pointer to a char pointer.  It is assumed that if *dst is non-NULL, it
 * was malloc'ed and needs to freed.  *dst will be set to a dup of src.
 */
static void qual_overwrite(char **dst, const char *src)
{
    if (!dst)
        return;

    free(*dst);
    *dst = NULL;

    if (!src || !*src)
        return;

    *dst = strdup(src);
}

void parse_banner(char *banner, atransport *t)
{
    static const char *prop_seps = ";";
    static const char key_val_sep = '=';
    char *cp;
    char *type;

    D("parse_banner: %s\n", banner);
    type = banner;
    cp = strchr(type, ':');
    if (cp) {
        *cp++ = 0;
        /* Nothing is done with second field. */
        cp = strchr(cp, ':');
        if (cp) {
            char *save;
            char *key;
            key = adb_strtok_r(cp + 1, prop_seps, &save);
            while (key) {
                cp = strchr(key, key_val_sep);
                if (cp) {
                    *cp++ = '\0';
                    if (!strcmp(key, "ro.product.name"))
                        qual_overwrite(&t->product, cp);
                    else if (!strcmp(key, "ro.product.model"))
                        qual_overwrite(&t->model, cp);
                    else if (!strcmp(key, "ro.product.device"))
                        qual_overwrite(&t->device, cp);
                }
                key = adb_strtok_r(NULL, prop_seps, &save);
            }
        }
    }

    if(!strcmp(type, "bootloader")){
        D("setting connection_state to CS_BOOTLOADER\n");
        t->connection_state = CS_BOOTLOADER;
        update_transports();
        return;
    }

    if(!strcmp(type, "device")) {
        D("setting connection_state to CS_DEVICE\n");
        t->connection_state = CS_DEVICE;
        update_transports();
        return;
    }

    if(!strcmp(type, "recovery")) {
        D("setting connection_state to CS_RECOVERY\n");
        t->connection_state = CS_RECOVERY;
        update_transports();
        return;
    }

    if(!strcmp(type, "sideload")) {
        D("setting connection_state to CS_SIDELOAD\n");
        t->connection_state = CS_SIDELOAD;
        update_transports();
        return;
    }

    t->connection_state = CS_HOST;
}

void handle_packet(apacket *p, atransport *t)
{
    asocket *s;

    D("handle_packet() %c%c%c%c\n", ((char*) (&(p->msg.command)))[0],
            ((char*) (&(p->msg.command)))[1],
            ((char*) (&(p->msg.command)))[2],
            ((char*) (&(p->msg.command)))[3]);
    print_packet("recv", p);

    switch(p->msg.command){
    case A_SYNC:
        if(p->msg.arg0){
            send_packet(p, t);
            if(HOST) send_connect(t);
        } else {
            t->connection_state = CS_OFFLINE;
            handle_offline(t);
            send_packet(p, t);
        }
        return;

    case A_CNXN: /* CONNECT(version, maxdata, "system-id-string") */
            /* XXX verify version, etc */
        if(t->connection_state != CS_OFFLINE) {
            t->connection_state = CS_OFFLINE;
            handle_offline(t);
        }

        parse_banner((char*) p->data, t);

        if (HOST || !auth_enabled) {
            handle_online(t);
            if(!HOST) send_connect(t);
        } else {
            //send_auth_request(t);
        }
        break;

    case A_AUTH:
        break;

    case A_OPEN: /* OPEN(local-id, 0, "destination") */
        if (t->online) {
            char *name = (char*) p->data;
            name[p->msg.data_length > 0 ? p->msg.data_length - 1 : 0] = 0;
            s = create_local_service_socket(name);
            if(s == 0) {
                send_close(0, p->msg.arg0, t);
            } else {
                s->peer = create_remote_socket(p->msg.arg0, t);
                s->peer->peer = s;
                send_ready(s->id, s->peer->id, t);
                s->ready(s);
            }
        }
        break;

    case A_OKAY: /* READY(local-id, remote-id, "") */
        if (t->online) {
            if((s = find_local_socket(p->msg.arg1))) {
                if(s->peer == 0) {
                    s->peer = create_remote_socket(p->msg.arg0, t);
                    s->peer->peer = s;
                }
                s->ready(s);
            }
        }
        break;

    case A_CLSE: /* CLOSE(local-id, remote-id, "") */
        if (t->online) {
            if((s = find_local_socket(p->msg.arg1))) {
                s->close(s);
            }
        }
        break;

    case A_WRTE:
        if (t->online) {
            if((s = find_local_socket(p->msg.arg1))) {
                unsigned rid = p->msg.arg0;
                p->len = p->msg.data_length;

                if(s->enqueue(s, p) == 0) {
                    D("Enqueue the socket\n");
                    send_ready(s->id, rid, t);
                }
                return;
            }
        }
        break;

    default:
        printf("handle_packet: what is %08x?!\n", p->msg.command);
    }

    put_apacket(p);
}

alistener listener_list = {
    .next = &listener_list,
    .prev = &listener_list,
};

static void adb_cleanup(void)
{
    usb_cleanup();
}


void start_device_log(void)
{
    int fd;
    char    path[PATH_MAX];
    struct tm now;
    time_t t;
    char value[PROPERTY_VALUE_MAX];

    // read the trace mask from persistent property persist.adb.trace_mask
    // give up if the property is not set or cannot be parsed
    //property_get("persist.adb.trace_mask", value, "");
    if (sscanf(value, "%x", &adb_trace_mask) != 1)
        return;

    adb_mkdir("/data/adb", 0775);
    tzset();
    time(&t);
    localtime_r(&t, &now);
    strftime(path, sizeof(path),
                "/data/adb/adb-%Y-%m-%d-%H-%M-%S.txt",
                &now);
    fd = unix_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0640);
    if (fd < 0)
        return;

    // redirect stdout and stderr to the log file
    dup2(fd, 1);
    dup2(fd, 2);
    fprintf(stderr,"--- adb starting (pid %d) ---\n", getpid());
    adb_close(fd);

    fd = unix_open("/dev/null", O_RDONLY);
    dup2(fd, 0);
    adb_close(fd);
}


int adb_main(int is_daemon, int server_port)
{
    umask(000);

    atexit(adb_cleanup);

	propd_entry();

    init_transport_registration();

    if (access(USB_ADB_PATH, F_OK) == 0 || access(USB_FFS_ADB_EP0, F_OK) == 0) {
        // listen on USB
        usb_init();
    }

	//always init 
    local_init(DEFAULT_ADB_LOCAL_TRANSPORT_PORT);

    D("Event loop starting\n");

    fdevent_loop();

    usb_cleanup();

    return 0;
}


int main(int argc, char **argv)
{
    start_device_log();
    D("Handling main()\n");
    return adb_main(0, DEFAULT_ADB_PORT);
}
