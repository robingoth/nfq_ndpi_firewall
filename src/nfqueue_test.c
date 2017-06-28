#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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
int Quiet = 0;

struct nfq_handle *H;
struct nfq_q_handle *Qh;
struct ndpi_detection_module_struct *NdpiStruct;

struct Rules *RulesList;
int RuleCounter;

long long unsigned int BlockedPackets;
long long unsigned int AllowedPackets;
long long unsigned int ProtocolCounter[PROTOCOL_COUNT];

time_t OldMTime = 0;
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
    printf("daddr=%s ", inet_ntoa(*((struct in_addr *)&(ip_info->daddr))));
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
	    proto = detect_protocol(packet_data, payload_size, tv, NdpiStruct);
	    master_proto = ndpi_get_proto_name(NdpiStruct, proto.master_protocol);
	    app_proto = ndpi_get_proto_name(NdpiStruct, proto.app_protocol);;
	    
	    ProtocolCounter[proto.app_protocol]++;

	    if (!Quiet) {
		print_pkt(nfa, pkt_hdr, master_proto, app_proto);
	    }
	}
    }

    unsigned char *p_data;
    nfq_get_payload(nfa, &p_data);;
    struct iphdr *ip_info = (struct iphdr *)p_data;
    unsigned short dport;

    if (ip_info->protocol == IPPROTO_TCP) {
	struct tcphdr *tcp_info = (struct tcphdr *)(p_data + sizeof(*ip_info));
	dport = ntohs(tcp_info->dest);
    } else if (ip_info->protocol == IPPROTO_UDP) {
	struct udphdr *udp_info = (struct udphdr *)(p_data + sizeof(*ip_info));
	dport = ntohs(udp_info->dest);
    } else {
	dport = 0;
    }

    char *src = inet_ntoa(*((struct in_addr *)&(ip_info->saddr)));
    char *dst = inet_ntoa(*((struct in_addr *)&(ip_info->daddr)));

    u_int32_t verdict = NF_ACCEPT;
    
    int i = 0;
    for (i = 0; i < RuleCounter; i++) {
	struct Rule *cur = &RulesList->rules[i];
	
	if (is_match(cur, src, dst, dport, master_proto, app_proto) == 1) {
	    switch (cur->policy) {
		case ALLOW:
		    verdict = NF_ACCEPT;
		    break;
		case DENY:
		    verdict = NF_DROP;
		    BlockedPackets++;
		    break;
		case REJECT:
		    // TODO implement reject
		    verdict = NF_DROP;
		    BlockedPackets++;
		    break;
		case ALLOW_WITH_IPS:
		    verdict = (1 << 16) | NF_QUEUE;
		    AllowedPackets++;
		    break;
		default:
		    printf("ERROR: Policy is invalid.\n");
		    exit(1);
	    }
	    // exit the loop in case of match
	    break;
	} 
    }
    
    if (verdict == NF_ACCEPT) {
	AllowedPackets++;	
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

    printf("Number of allowed packets: \t%lld\n", AllowedPackets);
    printf("Number of blocked packets: \t%lld\n", BlockedPackets);

    printf("\n");

    printf("Protocol statictics:\n\n");
    // print number of packets per protocol
    for (i = 0; i < PROTOCOL_COUNT; i++) {
	if (ProtocolCounter[i] != 0) {
	    
	    proto_name = ndpi_get_proto_name(NdpiStruct, i);
	    printf("%s:\t\t%llu\n", proto_name, ProtocolCounter[i]);
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
    nfq_destroy_queue(Qh);

    printf("closing library handle\n");
    nfq_close(H);

    print_results();
    
    printf("Exiting nDPI detection module.\n");
    ndpi_exit_detection_module(NdpiStruct);
    
    exit(0);
}

void update_rules(char *filepath)
{
    struct stat file_stat;
    int err = stat(filepath, &file_stat);
    if (err != 0) {
	perror(" [file_is_modified] stat ");
	exit(1);
    }

    if (file_stat.st_mtime > OldMTime) {
	OldMTime = file_stat.st_mtime;
	
	struct Connection *conn = rules_open(filepath, 'g');
	RulesList = rules_get(conn);

	if (RulesList == NULL) {
	    printf("Unable to retrieve rules.\n");
	    exit(1);
	}

	int c = 0;
	for (c = 0; c < MAX_RULES; c++) {
	    struct Rule *cur = &RulesList->rules[c];
	    if(cur->set == 1) {
		RuleCounter++;
	    }
	}
    }

    if (!Quiet) {
	printf("\nCurrent set of Rules:\n");

	int i = 0;
    	for (i = 0; i < MAX_RULES; i++) {
    	    struct Rule *cur = &RulesList->rules[i];
    	    if (cur->set == 1) {
    	        rule_print(cur, i);
    	    }
    	}
	printf("\n");
    }
}

int main(int argc, char **argv) 
{
    if (argc > 3 || argc < 2) {
	printf("Usage:\n./ndpi_nfqueue_firewall blacklist_path [-q]\n");
	printf("Input arguments:\n");
	printf("\tq:\tQuiet mode. If set, does not print every packet's details.\n");
	exit(1);
    }

    if (argc == 3) {
	if (strcmp(argv[2], "-q") == 0) {
	    Quiet = 1;
	} else {
	    printf("Invalid flag %s\n", argv[2]);
	    exit(1);
	}
    }

    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    
    char *rules_file_path = argv[1];

    // initialize protocol counter array to zeroes
    int pc = 0;
    for (pc = 0; pc < PROTOCOL_COUNT; pc++) {
	ProtocolCounter[pc] = 0;
    }

    H = nfq_open();
    if (!H) {
	fprintf(stderr, "error during nfq_open()\n");
	exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(H, AF_INET) < 0) {
	fprintf(stderr, "erorr during nfq_unbind_pf()\n");
	exit(1);
    }

    printf("binding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_bind_pf(H, AF_INET) < 0) {
        fprintf(stderr, "erorr during nfq_bind_pf()\n");
	exit(1);
    }

    printf("binding this socket to queue '0'\n");
    Qh = nfq_create_queue(H, 0, &cb, NULL);
    if (!Qh) {
	fprintf(stderr, "error during nfq_create_queue()\n");
	exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(Qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
	fprintf(stderr, "can't set packet_copy mode\n");
	exit(1);
    }
    
    fd = nfq_fd(H);
    
    signal(SIGINT, sigint_handler);

    NdpiStruct = setup_detection();
  
    while ((rv = recv(fd, buf, sizeof(buf), 0)) != -1) {
	update_rules(rules_file_path);
	if (!Quiet) {
	    printf("%d bytes received\n", rv);
	}	
	nfq_handle_packet(H, buf, rv);
    }

    printf("shouldn't reach here");

    return 0;
}
