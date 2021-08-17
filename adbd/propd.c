//
// Copyright 2007 The Android Open Source Project
//
// Property sever.  Mimics behavior provided on the device by init(8) and
// some code built into libc.

#define NELEM(x) ((int) (sizeof(x) / sizeof((x)[0])))
#include "propd.h"
#include "list.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdarg.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <poll.h>
#include <fcntl.h>
#include <stddef.h>
#include <dirent.h>

//C++ code define
#ifndef bool
typedef unsigned char bool;
#endif

#ifndef true
#define true (1)
#endif

#ifndef false
#define false (0)
#endif

bool set_property(const char* key, const char* value);



static int persistent_properties_loaded = 0;
static int     listen_sock;
static pthread_t thread_id;
#define PERSISTENT_PROPERTY_DIR   "/fac/prop/"

list_declare(prop_list);

/*
 * Clear out the list.
 */
void clear_properties(void)
{

}

/*
 * Set default values for several properties.
 */
void set_default_properties(void)
{
    static const struct {
        const char* key;
        const char* value;
    } propList[] = {
        { "ro.proccess.name", "adbd prop service" },
    };

    for (int i = 0; i < NELEM(propList); i++)
        set_property(propList[i].key, propList[i].value);

}

/*
 * Get the value of a property.
 *
 * "valueBuf" must hold at least PROPERTY_VALUE_MAX bytes.
 *
 * Returns "true" if the property was found.
 */
bool get_property(const char* key, char* valueBuf)
{
    assert(key != NULL);
    assert(valueBuf != NULL);

	struct listnode *node;
	Property *prop;


    list_for_each(node, &prop_list) {
        prop = node_to_item(node, Property, plist);
        if (strcmp(prop->key, key) == 0) {
            if (strlen(prop->value) >= PROPERTY_VALUE_MAX) {
                fprintf(stderr,
                    "GLITCH: properties table holds '%s' '%s' (len=%d)\n",
                    prop->key, prop->value, (int) strlen(prop->value));
                abort();
            }
            assert(strlen(prop->value) < PROPERTY_VALUE_MAX);
            strcpy(valueBuf, prop->value);
            return true;
        }
    }

    //printf("Prop: get [%s] not found\n", key);
    return false;
}

/*
 * Set the value of a property, replacing it if it already exists.
 *
 * If "value" is NULL, the property is removed.
 *
 * If the property is immutable, this returns "false" without doing
 * anything.  (Not implemented.)
 */
bool set_property(const char* key, const char* value)
{
	struct listnode *node;
	Property *prop;
    assert(key != NULL);
    //assert(value != NULL);

    list_for_each(node, &prop_list) {
        prop = node_to_item(node, Property, plist);
        if (strcmp(prop->key, key) == 0) {
            if (value != NULL) {
                //printf("Prop: replacing [%s]: [%s] with [%s]\n",
                 //   prop->key, prop->value, value);
                strcpy(prop->value, value);
            } else {
                //printf("Prop: removing [%s]\n", prop->key);
                list_remove(node);
				free(prop);
            }
            return true;
        }
    }

    //printf("Prop: adding [%s]: [%s]\n", key, value);
    Property *new = malloc(sizeof(Property));
    strcpy(new->key, key);
    strcpy(new->value, value);
	list_add_tail(&prop_list, &(new->plist));

    return true;
}

static void write_peristent_property(const char *name, const char *value)
{
    const char *tempPath = PERSISTENT_PROPERTY_DIR "/.temp";
    char path[PATH_MAX];
    int fd, length;

    snprintf(path, sizeof(path), "%s/%s", PERSISTENT_PROPERTY_DIR, name);

    fd = open(tempPath, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    if (fd < 0) {
        printf("Unable to write persistent property to temp file %s errno: %d\n", tempPath, errno);
        return;   
    }
    write(fd, value, strlen(value));
    close(fd);

    if (rename(tempPath, path)) {
        unlink(tempPath);
        printf("Unable to rename persistent property file %s to %s\n", tempPath, path);
    }
}

int property_set(const char *key, const char *value)
{
    if (persistent_properties_loaded &&
            strncmp("persist.", key, strlen("persist.")) == 0) {
        /* 
         * Don't write properties to disk until after we have read all default properties
         * to prevent them from being overwritten by default values.
         */
        write_peristent_property(key, value);
    }

    if (strncmp("ctrl.", key, strlen("ctrl.")) == 0) {
        //service_ctrl_handle(key, value);
    }

	//printf("%s, %s\n", key, value);
	return set_property(key, value);
}

bool create_list_file(const char* fileName)
{

    struct stat sb;
    bool result = false;
    FILE *fp = NULL;
    int cc;
	char lineBuf[PROPERTY_KEY_MAX + PROPERTY_VALUE_MAX + 20];

    cc = stat(fileName, &sb);
    if (cc < 0) {
        if (errno != ENOENT) {
            printf(
                "Unable to stat '%s' (errno=%d)\n", fileName, errno);
            goto bail;
        }
    } else {
        /* don't touch it if it's not a socket */
        if (!(S_ISREG(sb.st_mode))) {
            printf(
                "File '%s' exists and is not a reg file\n", fileName);
            goto bail;
        }

        /* remove the cruft */
        if (unlink(fileName) < 0) {
            printf(
                "Unable to remove '%s' (errno=%d)\n", fileName, errno);
            goto bail;
        }
    }	

	fp = fopen(fileName, "w");

	struct listnode *node;
	Property *prop;

    list_for_each(node, &prop_list) {
        prop = node_to_item(node, Property, plist);
		memset(lineBuf, 0x00, sizeof(lineBuf));
		sprintf(lineBuf, "%s: [%s]\n", prop->key, prop->value);
		//printf("%s,%s\n", prop.key, prop.value);
        fputs(lineBuf, fp);
    }

    if (fp != NULL)
        fclose(fp);

	return true;

bail:
    if (fp != NULL)
        fclose(fp);
    return result;
}


/*
 * Create a UNIX domain socket, carefully removing it if it already
 * exists.
 */
bool create_socket(const char* fileName)
{
    struct stat sb;
    bool result = false;
    int sock = -1;
    int cc;

    cc = stat(fileName, &sb);
    if (cc < 0) {
        if (errno != ENOENT) {
            printf(
                "Unable to stat '%s' (errno=%d)\n", fileName, errno);
            goto bail;
        }
    } else {
        /* don't touch it if it's not a socket */
        if (!(S_ISSOCK(sb.st_mode))) {
            printf(
                "File '%s' exists and is not a socket\n", fileName);
            goto bail;
        }

        /* remove the cruft */
        if (unlink(fileName) < 0) {
            printf(
                "Unable to remove '%s' (errno=%d)\n", fileName, errno);
            goto bail;
        }
    }

    struct sockaddr_un addr;

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        printf(
            "UNIX domain socket create failed (errno=%d)\n", errno);
        goto bail;
    }

    /* bind the socket; this creates the file on disk */
    strcpy(addr.sun_path, fileName);    // max 108 bytes
    addr.sun_family = AF_UNIX;
    cc = bind(sock, (struct sockaddr*) &addr, SUN_LEN(&addr));
    if (cc < 0) {
        printf("AF_UNIX bind failed for '%s' (errno=%d)\n", fileName, errno);
        goto bail;
    }

    cc = listen(sock, 5);
    if (cc < 0) {
        printf("AF_UNIX listen failed (errno=%d)\n", errno);
        goto bail;
    }

    listen_sock = sock;
    sock = -1;
    result = true;

bail:
    if (sock >= 0)
        close(sock);
    return result;
}

/*
 * Handle a client request.
 *
 * Returns true on success, false if the fd should be closed.
 */
bool handle_request(int fd)
{
    char reqBuf[PROPERTY_KEY_MAX + PROPERTY_VALUE_MAX];
    char valueBuf[1 + PROPERTY_VALUE_MAX];
    ssize_t actual;

    memset(valueBuf, 'x', sizeof(valueBuf));        // placate valgrind

    /* read the command byte; this determines the message length */
    actual = read(fd, reqBuf, 1);
    if (actual <= 0)
        return false;

    if (reqBuf[0] == kSystemPropertyGet) {
        actual = read(fd, reqBuf, PROPERTY_KEY_MAX);

        if (actual != PROPERTY_KEY_MAX) {
            fprintf(stderr, "Bad read on get: %d of %d\n",
                (int) actual, PROPERTY_KEY_MAX);
            return false;
        }
        if (get_property(reqBuf, valueBuf+1))
            valueBuf[0] = 1;
        else
            valueBuf[0] = 0;
        //printf("GET property [%s]: (found=%d) [%s]\n",
        //    reqBuf, valueBuf[0], valueBuf+1);
        if (write(fd, valueBuf, sizeof(valueBuf)) != sizeof(valueBuf)) {
            fprintf(stderr, "Bad write on get\n");
            return false;
        }
    } else if (reqBuf[0] == kSystemPropertySet) {
        actual = read(fd, reqBuf, PROPERTY_KEY_MAX + PROPERTY_VALUE_MAX);
        if (actual != PROPERTY_KEY_MAX + PROPERTY_VALUE_MAX) {
            fprintf(stderr, "Bad read on set: %d of %d\n",
                (int) actual, PROPERTY_KEY_MAX + PROPERTY_VALUE_MAX);
            return false;
        }
        //printf("SET property '%s'\n", reqBuf);
        if (property_set(reqBuf, reqBuf + PROPERTY_KEY_MAX))
            valueBuf[0] = 1;
        else
            valueBuf[0] = 0;
        if (write(fd, valueBuf, 1) != 1) {
            fprintf(stderr, "Bad write on set\n");
            return false;
        }
    } else if (reqBuf[0] == kSystemPropertyList) {
        /* TODO */
        //assert(false);
		create_list_file(SYSTEM_PROPERTY_LIST_NAME);
        valueBuf[0] = 1;
        if (write(fd, valueBuf, 1) != 1) {
            fprintf(stderr, "Bad write on set\n");
            return false;
        }			
    } else {
        fprintf(stderr, "Unexpected request %d from prop client\n", reqBuf[0]);
        return false;
    }

    return true;
}

/*
 * Serve up properties.
 */
void serve_properties(void)
{
    //typedef List<int>::iterator IntIter;
    struct pollfd ufds[1];
	int fd_count = 1;
    ufds[0].fd = listen_sock;
    ufds[0].events = POLLIN;
	int fd;

    while (true) {
        int cc;
        int nr, i, timeout = -1;

        for (i = 0; i < fd_count; i++)
            ufds[i].revents = 0;
        nr = poll(ufds, fd_count, timeout);
        if (nr <= 0)
            continue;

        if (ufds[0].revents == POLLIN)


        if (ufds[0].revents == POLLIN) {
            struct sockaddr_un from;
            socklen_t fromlen;
            int newSock;

            fromlen = sizeof(from);
            newSock = accept(listen_sock, (struct sockaddr*) &from, &fromlen);
            if (newSock < 0) {
                printf(
                    "AF_UNIX accept failed (errno=%d)\n", errno);
            } else {
                //printf("new props connection on %d --> %d\n",
                //    mListenSock, newSock);

				fd = newSock;
            }


            bool ok = true;


            ok = handle_request(fd);

            if (ok) {

            } else {
                //printf("--- closing %d\n", fd);
                close(fd);
            }
        }
    }
}
void prop_load_persistent_properties()
{
    DIR* dir = opendir(PERSISTENT_PROPERTY_DIR);
    struct dirent*  entry;
    char path[PATH_MAX];
    char value[PROPERTY_VALUE_MAX];
    int fd, length;

    if (dir) {
        while ((entry = readdir(dir)) != NULL) {
            if (strncmp("persist.", entry->d_name, strlen("persist.")))
                continue;
#if HAVE_DIRENT_D_TYPE
            if (entry->d_type != DT_REG)
                continue;
#endif
            /* open the file and read the property value */
            snprintf(path, sizeof(path), "%s/%s", PERSISTENT_PROPERTY_DIR, entry->d_name);
            fd = open(path, O_RDONLY);
            if (fd >= 0) {
                length = read(fd, value, sizeof(value) - 1);
                if (length >= 0) {
                    value[length] = 0;
                    property_set(entry->d_name, value);
                } else {
                    printf("Unable to read persistent property file %s errno: %d\n", path, errno);
                }
                close(fd);
            } else {
                printf("Unable to open persistent property file %s errno: %d\n", path, errno);
            }
        }
        closedir(dir);
    } else {
        printf("Unable to open persistent property directory %s errno: %d\n", PERSISTENT_PROPERTY_DIR, errno);
    }
    
    persistent_properties_loaded = 1;
}

void prop_print_list()
{
	struct listnode *node;
	Property *prop;

    list_for_each(node, &prop_list) {
        prop = node_to_item(node, Property, plist);
        printf("Prop: [%s]: [%s]\n",
        prop->key, prop->value);
    }	
}

void propd_entry_thread(void)
{
	printf("Propd thread init\n");
    
    if (create_socket(SYSTEM_PROPERTY_PIPE_NAME)) {
        assert(listen_sock >= 0);

        set_default_properties();

		//prop_load_persistent_properties();
		//print_list();

        /* loop until it's time to exit or we fail */
        serve_properties();

        clear_properties();

        /*
         * Close listen socket and all clients.
         */
        printf("Cleaning up socket list\n");
        close(listen_sock);
    }

    printf("PropertyServer thread exiting\n");
    return;
}

/*
 * Thread entry point.
 *
 * This just sits and waits for a new connection.  It hands it off to the
 * main thread and then goes back to waiting.
 *
 * There is currently no "polite" way to shut this down.
 */
void propd_entry(void)
{
    pthread_create(&thread_id, NULL, 
        propd_entry_thread, NULL);

    pthread_setname_np(thread_id, "prop service");

    return;
}

