#include <conntrack_helper.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnfnetlink/linux_nfnetlink.h>

#include "ndpi_helper.h"

#define VERSION 1.0
#define BUFFERSIZE 65535

struct q_data {
    int id;
    struct nfq_handle *handle;
    struct nfq_q_handle *q_handle;
    struct nfnl_handle *nh;
    struct ndpi_workflow *workflow;
    int fd;
    int sockfd;
};

// Globals
pthread_mutex_t mutex, mutex_c, mutex_pt;
int Quiet = 0;
int NumQueues = 1;
int NumRoots = 512; 
int MaxFlows = 200000000;
int IdleScanPeriod = 10; 
int MaxIdleTime = 600; 
int MaxIdleFlows = 1024;

int Errors = 0;

void t_printf(int tid, char *format, ...);

void print_pkt (int tid, struct nfq_data *tb, struct nfqnl_msg_packet_hdr *pkt_hdr, 
	char *src_ip, char *dst_ip, unsigned short src_port, unsigned short dst_port,
	char *master_protocol, char *app_protocol)
{
    int id = 0;
    struct nfqnl_msg_packet_hw *hwph;

    t_printf(tid, "");

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
    if (t_data->workflow->last_idle_scan.tv_sec + IdleScanPeriod < tv.tv_sec) {
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
    printf("Queue %d: ", tid);
    vfprintf(stdout, format, ap);
    va_end(ap);
}

void *process_thread(void *data)
{
    ssize_t rv;
    int opt;
    char buf[BUFFERSIZE];

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

    t_printf(t_data->id, "setting buffer size to %d\n", BUFFERSIZE);
    nfnl_rcvbufsiz(nfq_nfnlh(t_data->handle), BUFFERSIZE);

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
    t_data->nh = nfq_nfnlh(t_data->handle);
    t_data->sockfd = nfnl_fd(t_data->nh);

    opt = 1;
    if (setsockopt(t_data->sockfd, SOL_NETLINK, NETLINK_NO_ENOBUFS, 
		&opt, sizeof(int)) == -1) {
	printf("ERROR: Can't set netlink enobufs: %s", strerror(errno));
    }

    // read packet and process it
    while (1) {
	rv = recv(t_data->fd, buf, BUFFERSIZE, 0);
	if (rv > 0) {
            pthread_mutex_lock(&mutex_pt);
	    nfq_handle_packet(t_data->handle, buf, rv);
	    pthread_mutex_unlock(&mutex_c);
	    pthread_mutex_unlock(&mutex_pt);
	} else {
	    if (rv < (ssize_t)-1 || rv > (ssize_t)BUFFERSIZE) {
		errno = EIO;
		break; /* out of the while (1) loop */
	    }

	    if (rv== (ssize_t)0) {
		errno = 0;
		break; /* No error, just netlink closed. Drop out. */
	    }
	    
	    if (rv == (ssize_t)-1) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {

		    /* Print overall statistics.
		     * */

		    continue;
		} else {
		    Errors++;
		    printf("Errors = %d\n", Errors);
		    break; /* Other errors drop out of the loop. */
		}
	    }
	}
    }

    t_printf(t_data->id, "unbinding from queue %d\n", t_data->id);
    nfq_destroy_queue(t_data->q_handle);

    t_printf(t_data->id, "closing library handle\n");
    nfq_close(t_data->handle);

    pthread_exit(NULL);
    return NULL;
}

void display_help()
{
    printf("NdpiNfqueueFirewall v.%.1f\n\n", VERSION);

    printf("Usage:\n");
    printf("NdpiNfqueueFirewall [ --option value ]...\n\n");
    
    printf("Options (default values in brackets):\n");
    printf("\t--num-queues\t\t-n\t\tNumber of queues to listen on.(1)\n");
    printf("\t--num-roots\t\t-r\t\tNumber of roots of a binary tree.(512)\n");
    printf("\t--max-flows\t\t-f\t\tMaximum number of flows.(200000000)\n");
    printf("\t--idle-scan-period\t-i\t\tTime period in seconds of scans for idle flows.(10s)\n");
    printf("\t--max-idle-time\t\t-t\t\tMaximum amount of time in seconds a flow can be idle.(600)\n");
    printf("\t--max-idle-flows\t-F\t\tMaximum number of idle flows.(1024)\n");
    printf("\t--quiet\t\t\t-q\t\tQuiet mode.\n");
    printf("\t--version\t\t-v\t\tDisplay version.\n");
    printf("\t--help\t\t\t-h\t\tDisplay help message.\n");
}

void print_setup(){
    printf("Configuration of this run is the following:\n");
    printf("\tnumber of queues \t %d\n", NumQueues);
    printf("\tnumber of roots \t %d\n", NumRoots);
    printf("\tmaximum flows \t\t %d\n", MaxFlows);
    printf("\tidle scan period \t %d\n", IdleScanPeriod);
    printf("\tmaximum idle time \t %d\n", MaxIdleTime);
    printf("\tmaximum idle flows \t %d\n", MaxIdleFlows);
    printf("\tquiet \t\t\t %d\n", Quiet);
}

int main(int argc, char **argv)
{
    int rc;
    void *status;
    
    if (argc > 14) {
	printf("Error: Too many arguments.\n");
	display_help();
	exit(1);
    }

    if (argc == 2) {
	if ((strcmp(argv[1], "-h") == 0) || (strcmp(argv[1], "--help") == 0)) {
    	    display_help();
    	    exit(0);
    	} else if ((strcmp(argv[1], "-v") == 0) || (strcmp(argv[1], "--version") == 0)) {
    	    printf("NdpiNfqueueFirewall version %.1f\n", VERSION);
    	    exit(0);
    	}
    }

    int a = 1;
    char *endptr;
    errno = 0;
    while (a < argc) {
	if ((strcmp(argv[a], "-n") == 0) || (strcmp(argv[a], "--num-queues") == 0)) {
	    // set num queues
	    NumQueues = strtoimax(argv[a + 1], &endptr, 10);
	    if ((errno != 0) || (NumQueues <= 0)) {
		printf("ERROR: %s is not a valid value.\n", argv[a + 1]);
		exit(1);
	    }
	    a += 2;
	} else if ((strcmp(argv[a], "-r") == 0) || (strcmp(argv[a], "--num-roots") == 0)) {
	    // set num roots
	    NumRoots = strtoimax(argv[a + 1], &endptr, 10);
	    if ((errno != 0) || (NumRoots <= 0)) {
		printf("ERROR: %s is not a valid value.\n", argv[a + 1]);
		exit(1);
	    }
	    a += 2;
	} else if ((strcmp(argv[a], "-f") == 0) || (strcmp(argv[a], "--max-flows") == 0)) {
	    // set max flows
	    MaxFlows = strtoimax(argv[a + 1], &endptr, 10);
	    if ((errno != 0) || (MaxFlows <= 0)) {
		printf("ERROR: %s is not a valid value.\n", argv[a + 1]);
		exit(1);
	    }
	    a += 2;
	} else if ((strcmp(argv[a], "-i") == 0) || (strcmp(argv[a], "--idle-scan-period") == 0)) {
	    // set idle scan period
	    IdleScanPeriod = strtoimax(argv[a + 1], &endptr, 10);
	    if ((errno != 0) || (IdleScanPeriod <= 0)) {
		printf("ERROR: %s is not a valid value.\n", argv[a + 1]);
		exit(1);
	    }
	    a += 2;
	} else if ((strcmp(argv[a], "-t") == 0) || (strcmp(argv[a], "--max-idle-time") == 0)) {
	    // set max idle time
	    MaxIdleTime = strtoimax(argv[a + 1], &endptr, 10);
	    if ((errno != 0) || (MaxIdleTime <= 0)) {
		printf("ERROR: %s is not a valid value.\n", argv[a + 1]);
		exit(1);
	    }
	    a += 2;
	} else if ((strcmp(argv[a], "-F") == 0) || (strcmp(argv[a], "--max-idle-flows") == 0)) {
	    // set max idle flows
	    MaxIdleFlows = strtoimax(argv[a + 1], &endptr, 10);
	    if ((errno != 0) || (MaxIdleFlows <= 0)) {
		printf("ERROR: %s is not a valid value.\n", argv[a + 1]);
		exit(1);
	    }
	    a += 2;
	} else if ((strcmp(argv[a], "-q") == 0) || (strcmp(argv[a], "--quiet") == 0)) {
	    Quiet = 1;
	    a += 1;
	} else {
	    printf("ERROR: %s is not a valid argument.\n", argv[a]);
	    display_help();
	    exit(1);
	}
    }

    print_setup();

    pthread_t threads[NumQueues];

    pthread_mutex_init(&mutex_c, NULL);
    pthread_mutex_init(&mutex_pt, NULL);
    
    struct q_data data[NumQueues];

    int i = 0;
    // prepare data for each thread
    for (i = 0; i < NumQueues; i++) {
	data[i].id = i + 10;

	struct ndpi_workflow *workflow = ndpi_calloc(1, sizeof(struct ndpi_workflow));
	if (workflow == NULL) {
	    printf("ERROR: workflow initialization failed");
	    exit(1);
	}

	workflow->num_roots = NumRoots;
	workflow->max_flows = MaxFlows;
	workflow->max_idle_time = MaxIdleTime;

	workflow->flow_count = 0;

	workflow->ndpi_flows_root = ndpi_calloc(workflow->num_roots, sizeof(void *));
	if (workflow->ndpi_flows_root == NULL) {
	    printf("ERROR: ndpi_flows_root initialization failed");
	    exit(1);
	}

	workflow->idle_flows = ndpi_calloc(MaxIdleFlows, sizeof(struct flow_info *));
	if (workflow->idle_flows == NULL) {
	    printf("ERROR: idle_flows initialization failed");
	    exit(1);
	}

	workflow->ndpi_struct = setup_detection();

	data[i].workflow = workflow;
    }

    // create threads
    for (i = 0; i < NumQueues; i++) {
	printf("Main: creating thread %d\n", i);
	rc = pthread_create(&threads[i], NULL, process_thread, &data[i]);

	if (rc) {
	    printf("ERROR; return code from pthread_create() is %d\n", rc);
	    exit(1);
	}
    }

    for (i = 0; i < NumQueues; i++) {
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
