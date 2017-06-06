#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "ndpi_helper.h"

// Globals
struct nfq_handle *h;
struct nfq_q_handle *qh;
// Forward definitions

/*
 *  prints some packet info and returns the packet ID
 */
static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;

    u_int32_t mark, ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
	id = ntohl(ph->packet_id);
	printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
    }

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

    ifi = nfq_get_indev(tb);
    if (ifi) {
	printf("indev=%u ", ifi);
    }

    ifi = nfq_get_outdev(tb);
    if (ifi) {
	printf("outdev=%u ", ifi);
    }

    ifi = nfq_get_physindev(tb);
    if (ifi) {
	printf("physindev=%u ", ifi);
    }

    ifi = nfq_get_physoutdev(tb);
    if (ifi) {
	printf("physoutdev=%u ", ifi);
    }

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0) {
	printf("payload_len=%d ", ret);
    }

    fputc('\n', stdout);

    return id;
}

/*
 *  A callback function called for each captured packet
 */
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, 
	struct nfq_data *nfa, void *data)
{
    char *proto;
    unsigned char *packet_data;
    u_int32_t id = print_pkt(nfa);
    // printf("entering callback\n");
    
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
	    //struct iphdr *ip_info = (struct iphdr *)&packet_data;
	    // unsigned short iphdr_size = ip_info->ihl << 2;

	    proto = detect_protocol(packet_data, payload_size, tv);

	    printf("proto = %s.\n", proto);
	}
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

/*
 *  handle SIGINT, terminate program
 */
void sigint_handler(int signum) 
{
    printf("Caught an SIGINT signal.\n");
    
    printf("unbinding from a queue '0'\n");
    nfq_destroy_queue(qh);

    printf("closing library handle\n");
    nfq_close(h);
    
    exit(0);
}

int main(int argc, char **argv) 
{
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    h = nfq_open();
    if (!h) {
	fprintf(stderr, "error during nfq_open()\n");
	exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
	fprintf(stderr, "erorr during nfq_unbind_pf()\n");
	exit(1);
    }

    printf("binding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "erorr during nfq_bind_pf()\n");
	exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
	fprintf(stderr, "error during nfq_create_queue()\n");
	exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
	fprintf(stderr, "can't set packet_copy mode\n");
	exit(1);
    }
    
    fd = nfq_fd(h);
    
    signal(SIGINT, sigint_handler);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
	printf("%d bytes received\n", rv);
	nfq_handle_packet(h, buf, rv);
    }

    return 0;
}
