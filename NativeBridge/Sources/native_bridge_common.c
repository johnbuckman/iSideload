#include "native_bridge_common.h"

#include <stdlib.h>

void native_bridge_free_string(char *ptr) {
    if (ptr) free(ptr);
}

void native_bridge_free(void *ptr) {
    if (ptr) free(ptr);
}
