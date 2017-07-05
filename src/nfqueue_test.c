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

#define NUM_QUEUES 3

struct q_data {
    int id;
    struct ndpi_detection_module_struct *ndpi_struct;
    struct nfq_handle *handle;
    struct nfq_q_handle *q_handle;
    int fd;
};

// Globals
pthread_mutex_t mutex, mutex_c, mutex_pt;

void print_pkt (int tid, struct nfq_data *tb, struct nfqnl_msg_packet_hdr *pkt_hdr, 
	char *master_protocol, char *app_protocol)
{
    int id = 0;
    struct nfqnl_msg_packet_hw *hwph;

    u_int32_t mark;
    int ret;
    unsigned char *data;

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

    mark = nfq_get_nfmark(tb);
    if (mark) {
	printf("mark=%u ", mark);
    }

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0) {
	printf("payload_len=%d ", ret);
    }

    struct iphdr *ip_info = (struct iphdr *)data;
    unsigned short dest_port;
    if (ip_info->protocol == IPPROTO_TCP) {
	struct tcphdr *tcp_info = (struct tcphdr *)(data + sizeof(*ip_info));
	dest_port = ntohs(tcp_info->dest);
    } else if (ip_info->protocol == IPPROTO_UDP) {
	struct udphdr *udp_info = (struct udphdr *)(data + sizeof(*ip_info));
	dest_port = ntohs(udp_info->dest);
    } else {
	dest_port = 0;
    }

    printf("saddr=%s ", inet_ntoa(*((struct in_addr *)&(ip_info->saddr))));
    printf("daddr=%s ", inet_ntoa(*((struct in_addr *)&(ip_info->daddr))));
    printf("dport=%d ", dest_port);

    fputc('\n', stdout);

    printf("proto = %s.%s.\n", master_protocol, app_protocol);
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	struct nfq_data *nfa, void *data)
{
    struct q_data *t_data = (struct q_data *)data;

    int id;
    struct ndpi_proto proto;
    char *app_proto; // e.g. Facebook
    char *master_proto; // e.g. HTTP
    unsigned char *packet_data;

    struct nfqnl_msg_packet_hdr *pkt_hdr = nfq_get_msg_packet_hdr(nfa);
    if (pkt_hdr) {
	id = ntohl(pkt_hdr->packet_id);
    } else {
	printf("Packet header could not be retrieved.\n");
	return -1; //error code of nfq_set_verdict
    }

    struct timeval tv;
    int is_success = nfq_get_timestamp(nfa, &tv);

    // if error
    if (is_success != 0) {
	printf("Timestamp was not retrieved. Skipping current packet.\n");
    } else {    
	unsigned short payload_size = nfq_get_payload(nfa, &packet_data);
	// if error
	if (payload_size == -1) {
	    printf("Packet payload was not retrieved. Skipping current packet.\n");
	} else {
	    proto = detect_protocol(packet_data, payload_size, tv, t_data->ndpi_struct);
	    master_proto = ndpi_get_proto_name(t_data->ndpi_struct, proto.master_protocol);
	    app_proto = ndpi_get_proto_name(t_data->ndpi_struct, proto.app_protocol);;

	    print_pkt(t_data->id, nfa, pkt_hdr, master_proto, app_proto);
	}
    }   

    pthread_mutex_lock(&mutex_c);
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

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

    struct q_data *t_data = (struct q_data *)data;

    t_data->ndpi_struct = setup_detection();

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
    
    struct q_data **data = malloc(NUM_QUEUES * sizeof(struct q_data *));
    if (data == NULL) {
	printf("Main: data allocation failed.\n");
	exit(1);
    }

    int t = 0;
    for (t = 0; t < NUM_QUEUES; t++) {
	data[t] = malloc(sizeof(struct q_data *));

	if (data[t] == NULL) {
    	    printf("Main: data allocation failed.\n");
    	    exit(1);
    	}
    }

    int i = 0;
    for (i = 0; i < NUM_QUEUES; i++) {
	data[i]->id = i;
	printf("Main: creating thread %d\n", data[i]->id);
	rc = pthread_create(&threads[i], NULL, process_thread, (void *)data[i]);

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
