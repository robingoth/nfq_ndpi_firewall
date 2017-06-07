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

// Globals
struct nfq_handle *h;
struct nfq_q_handle *qh;
struct ndpi_detection_module_struct *ndpi_struct;
char **blacklist;

// Forward declarations
int is_blacklisted(char *string);

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
	    proto = detect_protocol(packet_data, payload_size, tv, ndpi_struct);
	    printf("proto = %s.\n", proto);
	}
    }

    if (is_blacklisted(proto)) {
    	return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    } else {
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
}

/*
 *  checks if a string array contains a specified string
 *  IMPORTANT: last element of the string array must be NULL
 */
int is_blacklisted(char *string) 
{
    int i = 0;
    while (blacklist[i] != NULL) {
	if (!strcmp(string, blacklist[i])) {
	    return 1;
	}
	i++;
    }
    return 0;
}

/*
 * checks if string consists of -_0..9 a..z A..Z only
 */
int is_proto_name_valid(char *name)
{
    int result;
    int i = 0;
    for (i = 0; i < strlen(name); i++) {
	if ((name[i] >= 48 && name[i] <= 57) || 
		(name[i] >= 65 && name[i] <= 90) || 
		(name[i] >= 97 && name[i] <= 122) || 
		name[i] == 45 || name[i] == 95) {
	    result = 1;
	} else {
	    return 0;
	}
    }

    return result;
}

/*
 *  read the list of blacklisted protocols from file
 *  
 *  Inputs: 
 *	fileapth - path to file
 *  Return values:
 *	array of protocol names if successfull
 *	NULL in case of error
 */
char **get_blacklist(char *filepath)
{
    char **result = NULL;
    char **result_tmp = NULL;
    FILE *fp;
    char current_line[256];
    
    fp = fopen(filepath, "r");
    if (fp == NULL) {
	printf("Could not open the file %s\n", filepath);
	return NULL;
    }
    
    int line_num = 0;
    while (fgets(current_line, sizeof(current_line), fp)) {
	current_line[strlen(current_line) - 1] = '\0';
	
	if (!is_proto_name_valid(current_line)) {
	    printf("Protocol name %s is invalid.\n", current_line);
	} else {
	    result_tmp = (char **)realloc(result, (line_num + 1) * sizeof(char *));

	    if(result_tmp != NULL) {
		result = result_tmp;
	    
		result[line_num] = malloc(sizeof(char) * strlen(current_line));
		strcpy(result[line_num], current_line);
	    } else {
		printf("Memory could not be reallocated.\n");
		return NULL;
	    }
    
	    line_num++;
	}
    }

    fclose(fp);

    result_tmp = (char **)realloc(result, (line_num) * sizeof(char *));
    if (result_tmp != NULL) {
	result = result_tmp;

	result[line_num] = NULL;
    } else {
	printf("Memory could not be reallocated.\n");
	return NULL;
    }

    return result;
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
    if (argc != 2) {
	printf("Usage:\n./ndpi_nfqueue_firewall blacklist_path\n");
	exit(-1);
    }

    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    
    char *blacklist_file_path = argv[1];

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
	exit(-1);
    }

    printf("Blacklisted protocols are:\n");
    
    int i = 0;
    while (blacklist[i] != NULL) {
	if (blacklist[i] != NULL) {
	    printf("%s\n", blacklist[i]);
	}
	i++;
    }

    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
	printf("%d bytes received\n", rv);
	nfq_handle_packet(h, buf, rv);
    }

    return 0;
}
