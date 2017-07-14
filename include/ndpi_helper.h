#include <ndpi_main.h>

#define SIZEOF_FLOW_STRUCT (sizeof(struct ndpi_flow_struct))
#define TICK_RESOLUTION 1000

// STRUCTS
struct ndpi_workflow {
    int num_roots;
    int max_flows;
    int flow_count;

    void **ndpi_flows_root;

    struct ndpi_detection_module_struct *ndpi_struct;
};

struct flow_info {
    struct ndpi_flow_struct *ndpi_flow;
    
    u_int32_t src_ip;
    u_int32_t dst_ip;
    u_int16_t src_port;
    u_int16_t dst_port;
    
    u_int32_t hash_value;

    int detection_completed;
    int protocol;
    
    int packets;

    // result only 
    ndpi_protocol detected_protocol;

    void *src_id;
    void *dst_id;

    struct timeval last_seen;

    struct {
	char client_info[48], server_info[48];
    } ssh_ssl;
};

struct ndpi_detection_module_struct *setup_detection();

struct ndpi_proto detect_protocol(const unsigned char *packet, 
			const unsigned short packetlen, 
			struct timeval timestamp,  
			struct ndpi_workflow *workflow);
