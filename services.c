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

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "sysdeps.h"

#define  TRACE_TAG  TRACE_SERVICES
#include "adb.h"
#include "file_sync_service.h"
#include "priv_service.h"

#include "sockets_libcutils.h"

typedef struct stinfo stinfo;

struct stinfo {
    void (*func)(int fd, void *cookie);
    int fd;
    void *cookie;
};


void *service_bootstrap_func(void *x)
{
    stinfo *sti = x;
    sti->func(sti->fd, sti->cookie);
    free(sti);
    return 0;
}

static int create_service_thread(void (*func)(int, void *), void *cookie)
{
    stinfo *sti;
    adb_thread_t t;
    int s[2];

    if(adb_socketpair(s)) {
        printf("cannot create service socket pair\n");
        return -1;
    }

    sti = malloc(sizeof(stinfo));
    if(sti == 0) fatal("cannot allocate stinfo");
    sti->func = func;
    sti->cookie = cookie;
    sti->fd = s[1];

    if(adb_thread_create( &t, service_bootstrap_func, sti)){
        free(sti);
        adb_close(s[0]);
        adb_close(s[1]);
        printf("cannot create service thread\n");
        return -1;
    }

    D("service thread started, %d:%d\n",s[0], s[1]);
    return s[0];
}

static int create_subprocess(const char *cmd, const char *arg0, const char *arg1, pid_t *pid)
{
    char *devname;
    int ptm;

    ptm = unix_open("/dev/ptmx", O_RDWR); // | O_NOCTTY);
    if(ptm < 0){
        printf("[ cannot open /dev/ptmx - %s ]\n",strerror(errno));
        return -1;
    }
    fcntl(ptm, F_SETFD, FD_CLOEXEC);

    if(grantpt(ptm) || unlockpt(ptm) ||
       ((devname = (char*) ptsname(ptm)) == 0)){
        printf("[ trouble with /dev/ptmx - %s ]\n", strerror(errno));
        adb_close(ptm);
        return -1;
    }

    *pid = fork();
    if(*pid < 0) {
        printf("- fork failed: %s -\n", strerror(errno));
        adb_close(ptm);
        return -1;
    }

    if(*pid == 0){
        int pts;

        setsid();

        pts = unix_open(devname, O_RDWR);
        if(pts < 0) {
            fprintf(stderr, "child failed to open pseudo-term slave: %s\n", devname);
            exit(-1);
        }

        dup2(pts, 0);
        dup2(pts, 1);
        dup2(pts, 2);

        adb_close(pts);
        adb_close(ptm);

        // set OOM adjustment to zero
        char text[64];
        snprintf(text, sizeof text, "/proc/%d/oom_adj", getpid());
        int fd = adb_open(text, O_WRONLY);
        if (fd >= 0) {
            adb_write(fd, "0", 1);
            adb_close(fd);
        } else {
           D("adb: unable to open %s\n", text);
        }
        execl(cmd, cmd, arg0, arg1, NULL);
        fprintf(stderr, "- exec '%s' failed: %s (%d) -\n",
                cmd, strerror(errno), errno);
        exit(-1);
    } else {
        // Don't set child's OOM adjustment to zero.
        // Let the child do it itself, as sometimes the parent starts
        // running before the child has a /proc/pid/oom_adj.
        // """adb: unable to open /proc/644/oom_adj""" seen in some logs.
        return ptm;
    }
}

#define SHELL_COMMAND "/bin/sh"
#define SHELL_BASH_COMMAND "/bin/bash"

static void subproc_waiter_service(int fd, void *cookie)
{
    pid_t pid = (pid_t)cookie;

    D("entered. fd=%d of pid=%d\n", fd, pid);
    for (;;) {
        int status;
        pid_t p = waitpid(pid, &status, 0);
        if (p == pid) {
            D("fd=%d, post waitpid(pid=%d) status=%04x\n", fd, p, status);
            if (WIFSIGNALED(status)) {
                D("*** Killed by signal %d\n", WTERMSIG(status));
                break;
            } else if (!WIFEXITED(status)) {
                D("*** Didn't exit!!. status %d\n", status);
                break;
            } else if (WEXITSTATUS(status) >= 0) {
                D("*** Exit code %d\n", WEXITSTATUS(status));
                break;
            }
         }
    }
    D("shell exited fd=%d of pid=%d err=%d\n", fd, pid, errno);
    if (SHELL_EXIT_NOTIFY_FD >=0) {
      int res;
      res = writex(SHELL_EXIT_NOTIFY_FD, &fd, sizeof(fd));
      D("notified shell exit via fd=%d for pid=%d res=%d errno=%d\n",
        SHELL_EXIT_NOTIFY_FD, pid, res, errno);
    }
}

static int create_subproc_thread(const char *name)
{
    stinfo *sti;
    adb_thread_t t;
    int ret_fd;
    pid_t pid;
    if(name) {
        ret_fd = create_subprocess(SHELL_COMMAND, "-c", name, &pid);
    } else {
		if (access(SHELL_BASH_COMMAND, F_OK) == 0) {
			ret_fd = create_subprocess(SHELL_BASH_COMMAND, "-", 0, &pid);//run Bash for CLI
        } else {
			ret_fd = create_subprocess(SHELL_COMMAND, "-", 0, &pid);
		}
    }
    D("create_subprocess() ret_fd=%d pid=%d\n", ret_fd, pid);

    sti = malloc(sizeof(stinfo));
    if(sti == 0) fatal("cannot allocate stinfo");
    sti->func = subproc_waiter_service;
    sti->cookie = (void*)pid;
    sti->fd = ret_fd;

    if(adb_thread_create( &t, service_bootstrap_func, sti)){
        free(sti);
        adb_close(ret_fd);
        printf("cannot create service thread\n");
        return -1;
    }

    D("service thread started, fd=%d pid=%d\n",ret_fd, pid);
    return ret_fd;
}

int service_to_fd(const char *name)
{
    int ret = -1;
    //printf("%s\n", name);

    if(!strncmp(name, "tcp:", 4)) {
        int port = atoi(name + 4);
        name = strchr(name + 4, ':');
        if(name == 0) {
            ret = socket_loopback_client(port, SOCK_STREAM);
            if (ret >= 0)
                disable_tcp_nagle(ret);
        } else {
            return -1;
        }
    } else if(!strncmp("dev:", name, 4)) {
        ret = unix_open(name + 4, O_RDWR);
    } else if(!HOST && !strncmp(name, "shell:", 6)) {
        if(0 == strncmp(name + 6, "p:", 2) && name[9]) {
            void* arg = strdup(name + 9);
            if(arg == 0) return -1;
            ret = create_service_thread(priv_service_proc, arg);
        } else {
            if(name[6]) {
                ret = create_subproc_thread(name + 6);
            } else {
                ret = create_subproc_thread(0);
            }
        }
    } else if(!strncmp(name, "sync:", 5)) {
        ret = create_service_thread(file_sync_service, NULL);
    }

    if (ret >= 0) {
        close_on_exec(ret);
    }
    return ret;
}
