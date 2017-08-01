#include <conntrack_helper.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "ndpi_helper.h"

#define NUM_QUEUES 4

struct q_data {
    int id;
    struct nfq_handle *handle;
    struct nfq_q_handle *q_handle;
    struct ndpi_workflow *workflow;
    int fd;
};

// Globals
pthread_mutex_t mutex, mutex_c, mutex_pt;
int Quiet = 0;

void t_printf(int tid, char *format, ...);

void print_pkt (int tid, struct nfq_data *tb, struct nfqnl_msg_packet_hdr *pkt_hdr, 
	char *src_ip, char *dst_ip, unsigned short src_port, unsigned short dst_port,
	char *master_protocol, char *app_protocol)
{
    int id = 0;
    struct nfqnl_msg_packet_hw *hwph;

    printf("Thread %d: ", tid);

    id = ntohl(pkt_hdr->packet_id);
    printf("id=%u ", id);

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
	int i, hlen = ntohs(hwph->hw_addrlen);

	printf("he_src_addr=");
	for (i = 0; i < hlen-1; i++) {
	    printf("%02x:", hwph->hw_addr[i]);
	}
	printf("%02x ", hwph->hw_addr[hlen - 1]);
    }

    printf("src=%s:%d dst=%s:%d\n", src_ip, src_port, dst_ip, dst_port);
    printf("proto = %s.%s.\n", master_protocol, app_protocol);
}

/*
 * Callback function called for each packet 
 */
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	struct nfq_data *nfa, void *data)
{
    // read thread-specific data
    struct q_data *t_data = (struct q_data *)data;

    int id;
    struct ndpi_proto proto;
    char *app_proto; // e.g. Facebook
    char *master_proto; // e.g. HTTP
    unsigned char *packet_data;

    char src_ip[15], dst_ip[15];

    struct nfqnl_msg_packet_hdr *pkt_hdr = nfq_get_msg_packet_hdr(nfa);
    if (pkt_hdr) {
	id = ntohl(pkt_hdr->packet_id);
    } else {
	t_printf(t_data->id, "Packet header could not be retrieved.\n");
	return -1; //error code of nfq_set_verdict
    }

    struct timeval tv;
    int is_success = nfq_get_timestamp(nfa, &tv);

    // if the timestamp was not retrieved, set it to local time
    if (is_success != 0 || tv.tv_sec == 0) {
	memset(&tv, 0, sizeof(struct timeval));
	gettimeofday(&tv, NULL);
    }

    unsigned short payload_size;
    payload_size = nfq_get_payload(nfa, &packet_data);

    if (payload_size == -1) {
	t_printf(t_data->id, "Packet payload was not retrieved. Skipping current packet.\n");
	return -1;
    }

    // detect protocol
    proto = detect_protocol(packet_data, payload_size, tv, t_data->workflow); 
    master_proto = ndpi_get_proto_name(t_data->workflow->ndpi_struct, proto.master_protocol);
    app_proto = ndpi_get_proto_name(t_data->workflow->ndpi_struct, proto.app_protocol);

    // determine source and destination
    struct iphdr *ip_info = (struct iphdr *)packet_data;
    char *src_ip_ptr = inet_ntoa(*((struct in_addr *)&(ip_info->saddr)));
    strncpy(src_ip, src_ip_ptr, sizeof(src_ip));
    char *dst_ip_ptr = inet_ntoa(*((struct in_addr *)&(ip_info->daddr)));
    strncpy(dst_ip, dst_ip_ptr, sizeof(dst_ip));

    unsigned short dst_port;
    unsigned short src_port;
    if (ip_info->protocol == IPPROTO_TCP) {
	struct tcphdr *tcp_info = (struct tcphdr *)(packet_data + sizeof(*ip_info));
	dst_port = ntohs(tcp_info->dest);
	src_port = ntohs(tcp_info->source);
    } else if (ip_info->protocol == IPPROTO_UDP) {
	struct udphdr *udp_info = (struct udphdr *)(packet_data + sizeof(*ip_info));
	dst_port = ntohs(udp_info->dest);
	src_port = ntohs(udp_info->source);
    } else {
	dst_port = src_port = 0;
    }

    // set connlabel
    int is_label_set = 0;
    if ((proto.app_protocol < 128) && (proto.master_protocol < 128)) {
	is_label_set = update_label(src_ip, dst_ip, src_port, dst_port, 
		proto.master_protocol, proto.app_protocol);	
    }
   

    if (!Quiet) {
	print_pkt(t_data->id, nfa, pkt_hdr, src_ip, dst_ip, src_port, dst_port, 
		    master_proto, app_proto);
    }

    // free idle flows
    t_data->workflow->timestamp = tv;
    if (t_data->workflow->last_idle_scan.tv_sec + IDLE_SCAN_PERIOD < tv.tv_sec) {
	t_data->workflow->last_idle_scan = t_data->workflow->timestamp;
	free_idle_flows(t_data->workflow);
    }

    // unlock happens in process_thread()
    pthread_mutex_lock(&mutex_c);
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

/*
 * Print wrapper for threads
 * Input arguments:
 *	tid - thread id
 *	format - string format like for printf()
 */
void t_printf(int tid, char *format, ...) 
{
    va_list ap;
    va_start(ap, format);
    printf("Thread %d: ", tid);
    vfprintf(stdout, format, ap);
    va_end(ap);
}

void *process_thread(void *data)
{
    int rv;
    char buf[4096] __attribute__ ((aligned));

    // retrieve thread-specific data
    struct q_data *t_data = (struct q_data *)data;

    t_printf(t_data->id, "opening library handle\n");
    t_data->handle = nfq_open();
    if (!t_data->handle) {
	t_printf(t_data->id, "error during nfq_open()\n");
	exit(1);
    }

    t_printf(t_data->id, "unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(t_data->handle, AF_INET) < 0) {
	t_printf(t_data->id, "error during nfq_unbind_pf()\n");
	exit(1);
    }

    t_printf(t_data->id, "binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(t_data->handle, AF_INET) < 0) {
	t_printf(t_data->id, "error during nfq_bind_pf()\n");
	exit(1);
    }

    t_printf(t_data->id, "binding this socket to queue '%d'\n", t_data->id);
    t_data->q_handle = nfq_create_queue(t_data->handle, t_data->id, &cb, (void *)t_data);
    if (!t_data->q_handle) {
	t_printf(t_data->id, "error during nfq_create_queue()\n");
	exit(1);
    }

    t_printf(t_data->id, "setting copy_packet mode\n");
    if (nfq_set_mode(t_data->q_handle, NFQNL_COPY_PACKET, 0xffff) < 0) {
	t_printf(t_data->id, "can't set packet_copy mode\n");
	exit(1);
    }
    
    t_data->fd = nfq_fd(t_data->handle);

    // read packet and process it
    while ((rv = recv(t_data->fd, buf, sizeof(buf), 0)) && rv >= 0) {
	pthread_mutex_lock(&mutex_pt);
	nfq_handle_packet(t_data->handle, buf, rv);
	pthread_mutex_unlock(&mutex_c);
	pthread_mutex_unlock(&mutex_pt);
    }

    t_printf(t_data->id, "unbinding from queue %d\n", t_data->id);
    nfq_destroy_queue(t_data->q_handle);

    t_printf(t_data->id, "closing library handle\n");
    nfq_close(t_data->handle);

    pthread_exit(NULL);
    return NULL;
}

int main(int argc, char **argv)
{
    pthread_t threads[NUM_QUEUES];
    int rc;
    void *status;

    pthread_mutex_init(&mutex_c, NULL);
    pthread_mutex_init(&mutex_pt, NULL);
    
    struct q_data data[NUM_QUEUES];

    int i = 0;
    // prepare data for each thread
    for (i = 0; i < NUM_QUEUES; i++) {
	data[i].id = i;

	struct ndpi_workflow *workflow = ndpi_calloc(1, sizeof(struct ndpi_workflow));
	if (workflow == NULL) {
	    printf("ERROR: thread data initialization failed");
	    exit(1);
	}

	workflow->num_roots = NUM_ROOTS;
	workflow->max_flows = MAX_FLOWS;
	workflow->flow_count = 0;

	workflow->ndpi_flows_root = ndpi_calloc(workflow->num_roots, sizeof(void *));
	if (workflow->ndpi_flows_root == NULL) {
	    printf("ERROR: thread data initialization failed");
	    exit(1);
	}

	workflow->ndpi_struct = setup_detection();

	data[i].workflow = workflow;
    }

    // create threads
    for (i = 0; i < NUM_QUEUES; i++) {
	printf("Main: creating thread %d\n", data[i].id);
	rc = pthread_create(&threads[i], NULL, process_thread, &data[i]);

	if (rc) {
	    printf("ERROR; return code from pthread_create() is %d\n", rc);
	    exit(1);
	}
    }

    for (i = 0; i < NUM_QUEUES; i++) {
	rc = pthread_join(threads[i], &status);
	if (rc) {
	    printf("ERROR; return code from pthread_join() is %d\n", rc);
	    exit(1);
	}

	printf("Main: completed join with thread %d having a status of %ld\n", i, (long)status);
    }

    printf("Main: program completed. Exiting.\n");
    
    pthread_mutex_destroy(&mutex_c);
    pthread_mutex_destroy(&mutex_pt);
    pthread_exit(NULL);
    exit(0);
}
