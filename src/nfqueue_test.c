#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "ndpi_helper.h"
#include "rule_helper.h"

// Preprocessor directives
#define PROTOCOL_COUNT NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1

// Globals
int quiet = 0;

struct nfq_handle *h;
struct nfq_q_handle *qh;
struct ndpi_detection_module_struct *ndpi_struct;
char **blacklist;

int blocked_packets;
int allowed_packets;

long long unsigned int protocol_counter[PROTOCOL_COUNT];

// Forward declarations

/*
 *  prints some packet info
 */
void print_pkt (struct nfq_data *tb, struct nfqnl_msg_packet_hdr *pkt_hdr, 
		char *master_protocol, char *app_protocol)
{
    int id = 0;
    struct nfqnl_msg_packet_hw *hwph;

    u_int32_t mark;
    int ret;
    unsigned char *data;

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
    printf("daddr=%s ", inet_ntoa(*((struct in_addr *)&(ip_info->saddr))));
    printf("dport=%d ", dest_port);

    fputc('\n', stdout);

    printf("proto = %s.%s.\n", master_protocol, app_protocol);
}

/*
 *  A callback function called for each captured packet
 */
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, 
	struct nfq_data *nfa, void *data)
{
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
	    proto = detect_protocol(packet_data, payload_size, tv, ndpi_struct);
	    master_proto = ndpi_get_proto_name(ndpi_struct, proto.master_protocol);
	    app_proto = ndpi_get_proto_name(ndpi_struct, proto.app_protocol);;
	    
	    protocol_counter[proto.app_protocol]++;

	    if (!quiet) {
		print_pkt(nfa, pkt_hdr, master_proto, app_proto);
	    }
	}
    }

    u_int32_t verdict;
    if (is_blacklisted(master_proto, blacklist)) {
	blocked_packets++;
	verdict = (1 << 16) | NF_QUEUE;
    } else {
	if (is_blacklisted(app_proto, blacklist)) {
	    blocked_packets++;
	    verdict = (1 << 16) | NF_QUEUE;
	} else {
	    allowed_packets++;
	    verdict = NF_ACCEPT;
	}
    }
    
    return nfq_set_verdict2(qh, id, verdict, 0xE, 0, NULL);
}

/*
 * prints results
 */
void print_results()
{
    int i = 0;
    char *proto_name;
    printf("*************************\n");
    printf("*\tRESULTS\t\t*\n");
    printf("*************************\n\n");

    printf("Number of allowed packets: \t%d\n", allowed_packets);
    printf("Number of blocked packets: \t%d\n", blocked_packets);

    printf("\n");

    printf("Protocol statictics:\n\n");
    // print number of packets per protocol
    for (i = 0; i < PROTOCOL_COUNT; i++) {
	if (protocol_counter[i] != 0) {
	    
	    proto_name = ndpi_get_proto_name(ndpi_struct, i);
	    printf("%s:\t\t%llu\n", proto_name, protocol_counter[i]);
	}
    }
    printf("\n");
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

    print_results();
    
    printf("Exiting nDPI detection module.\n");
    ndpi_exit_detection_module(ndpi_struct);
    
    exit(0);
}

int main(int argc, char **argv) 
{
    if (argc > 3 || argc < 2) {
	printf("Usage:\n./ndpi_nfqueue_firewall blacklist_path [-q]\n");
	printf("Input arguments:\n");
	printf("\tq:\tquiet mode. If set, does not print every packet's details.\n");
	exit(1);
    }

    if (argc == 3) {
	if (strcmp(argv[2], "-q") == 0) {
	    quiet = 1;
	} else {
	    printf("Invalid flag %s\n", argv[2]);
	    exit(1);
	}
    }

    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    
    char *blacklist_file_path = argv[1];

    // initialize protocol counter array to zeroes
    int pc = 0;
    for (pc = 0; pc < PROTOCOL_COUNT; pc++) {
	protocol_counter[pc] = 0;
    }

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

    ndpi_struct = setup_detection();
    blacklist = get_blacklist(blacklist_file_path);
   
    if (blacklist == NULL) {
	printf("An error occured when loading blacklist file");
	exit(1);
    }

    printf("Blacklisted protocols are:\n");
    
    int i = 0;
    while (blacklist[i] != NULL) {
	if (blacklist[i] != NULL) {
	    printf("%s\n", blacklist[i]);
	}
	i++;
    }

    while ((rv = recv(fd, buf, sizeof(buf), 0)) != -1) {
	if (!quiet) {
	    printf("%d bytes received\n", rv);
	}	
	nfq_handle_packet(h, buf, rv);
    }

    printf("shouldn't reach here");

    return 0;
}
