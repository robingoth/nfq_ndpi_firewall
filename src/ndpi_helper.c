#include <stdio.h>
#include <stdlib.h>

#include "ndpi_main.h"
#include "ndpi_helper.h"

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
struct ndpi_detection_module_struct *setup_detection()
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

    return ndpi_struct;
}

struct ndpi_flow_struct *create_ndpi_flow() 
{
    struct ndpi_flow_struct *ndpi_flow;
    
    if((ndpi_flow = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT)) == NULL) {
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_ERROR, "[NDPI] %s(2): not enough memory\n", __FUNCTION__);
    } else {
	memset(ndpi_flow, 0, SIZEOF_FLOW_STRUCT);
    }

    return ndpi_flow;
}

char *detect_protocol(const unsigned char *packet, 
			    const unsigned short packetlen, 
			    struct timeval timestamp,
			    struct ndpi_detection_module_struct *ndpi_struct)
{
    char *return_value;
    struct ndpi_id_struct *src, *dst;
    struct ndpi_flow_struct *ndpi_flow = NULL;
  
    ndpi_flow = create_ndpi_flow();

    src = ndpi_malloc(SIZEOF_ID_STRUCT);
    if (src == NULL) {
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_ERROR, "[NDPI] %s(3): not enough memory\n", __FUNCTION__);
	return(NULL);
    } else {
	memset(src, 0, SIZEOF_ID_STRUCT);
    }
    
    dst = ndpi_malloc(SIZEOF_ID_STRUCT);
    if (dst == NULL) {
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_ERROR, "[NDPI] %s(3): not enough memory\n", __FUNCTION__);
	return(NULL);
    } else {
	memset(dst, 0, SIZEOF_ID_STRUCT);
    }

    u_int64_t tick = ((uint64_t) timestamp.tv_sec) * TICK_RESOLUTION + 
	timestamp.tv_usec / (1000000 / TICK_RESOLUTION);

    struct ndpi_proto detected_protocol = ndpi_detection_process_packet(ndpi_struct, ndpi_flow, 
	   packet, packetlen, tick, src, dst);

    return_value = ndpi_get_proto_name(ndpi_struct, detected_protocol.app_protocol);
    
    ndpi_free(ndpi_flow);
    ndpi_free(src);
    ndpi_free(dst);

    return return_value;
}
