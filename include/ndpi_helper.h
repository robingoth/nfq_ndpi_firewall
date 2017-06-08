#include <ndpi_main.h>

#define SIZEOF_FLOW_STRUCT (sizeof(struct ndpi_flow_struct))
#define TICK_RESOLUTION 1000

/*
 *  malloc wrapper function
 */
static void *malloc_wrapper(size_t size);

/*
 * free wrapper function
 */
static void free_wrapper(void *freeable);

/*
 *  
 */
struct ndpi_detection_module_struct *setup_detection();

/*
 *
 */
struct ndpi_flow_struct *create_ndpi_flow();

/*
 *
 */
struct ndpi_proto detect_protocol(const unsigned char *packet, 
			const unsigned short packetlen, 
			struct timeval timestamp,  
			struct ndpi_detection_module_struct *ndpi_struct);
