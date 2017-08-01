#ifndef NDPI_HELPER_H_
#define NDPI_HELPER_H_

#include <ndpi_main.h>

#define SIZEOF_FLOW_STRUCT (sizeof(struct ndpi_flow_struct))
#define TICK_RESOLUTION 1000
#define NUM_ROOTS 512
#define MAX_FLOWS 200000000 
#define IDLE_SCAN_PERIOD 10
#define MAX_IDLE_TIME 600
#define MAX_IDLE_FLOWS 1024 

// Forward Declarations
struct flow_info;

// STRUCTS
struct ndpi_workflow {
    int num_roots;
    int max_flows;
    int flow_count;

    // root of the tree
    void **ndpi_flows_root;

    struct ndpi_detection_module_struct *ndpi_struct;

    // when the idle flows were last scanned
    struct timeval last_idle_scan;
    // timestamp equals to the timestamp of the last packet 
    struct timeval timestamp;

    // these 2 exist because idle flows cannot be deleted inline,
    // so they are added into a queue and deleted later
    unsigned int num_idle_flows;
    struct flow_info *idle_flows[MAX_IDLE_FLOWS];
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

// FUNCTIONS
struct ndpi_detection_module_struct *setup_detection();

struct ndpi_proto detect_protocol(const unsigned char *packet, 
			const unsigned short packetlen, 
			struct timeval timestamp,  
			struct ndpi_workflow *workflow);

void free_idle_flows(struct ndpi_workflow *workflow);

#endif // NDPI_HELPER_H_
