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
 *  free wrapper function
 */
static void free_wrapper(void *freeable) 
{
    free(freeable);
}

/*
 *  setup detection
 */

void setup_detection(void)
{
    NDPI_PROTOCOL_BITMASK all;
    
    set_ndpi_malloc(malloc_wrapper), set_ndpi_free(free_wrapper);
    set_ndpi_flow_malloc(NULL), set_ndpi_flow_free(NULL);

    struct ndpi_detection_module_struct *ndpi_struct = ndpi_init_detection_module();

    if (ndpi_struct == NULL) {
     	NDPI_LOG(0, NULL, NDPI_LOG_ERROR, "global structure initialization failed\n");
	exit(1);
    }

    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_struct, &all);
}

struct ndpi_proto detect_protocol()
{
    struct ndpi_id_struct *src, *dst;
    struct ndpi_flow_struct *ndpi_flow = NULL;

    u_int8_t proto;
    struct ndpi_tcphdr *tcph = NULL;
    struct ndpi_udphdr *udph = NULL;
    u_int16_t sport, dport, payload_len;
    u_int8_t *payload;
    u_int8_t src_to_dst_direction = 1;
    struct ndpi_proto nproto = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_UNKNOWN };

    
}
