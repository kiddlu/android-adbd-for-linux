#ifndef _PROPD_H
#define _PROPD_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <pthread.h>
#include "list.h"

#define PROPERTY_KEY_MAX   32
#define PROPERTY_VALUE_MAX  92
 
#define SYSTEM_PROPERTY_PIPE_NAME       "/tmp/linux-sysprop"
#define SYSTEM_PROPERTY_LIST_NAME       "/tmp/linux-sysprop-list"

enum {
    kSystemPropertyUnknown = 0,
    kSystemPropertyGet,
    kSystemPropertySet,
    kSystemPropertyList
};

/* one property entry */
typedef struct property {
    char    key[PROPERTY_KEY_MAX];
    char    value[PROPERTY_VALUE_MAX];

	struct listnode plist;
}Property;


void propd_entry(void);
void prop_print_list(void);
void prop_load_persistent_properties(void);

#endif//_PROPD_H
