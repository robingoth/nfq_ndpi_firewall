#include <stdio.h>
#include <stdlib.h>

#include "ndpi_main.h"

/*
 *  malloc wrapper function
 */
static void *malloc_wrapper(size_t size) 
{
    return malloc(size);
}

/*
 * free wrapper function
 */
static void free_wrapper(void *freeable) 
{
    free(freeable);
}
