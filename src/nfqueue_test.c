#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

// Globals
pthread_mutex_t mutex, mutex_c, mutex_pt;

/* returns packet id */
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
	printf("hw_protocol=0x%04x hook=%u id=%u ",
		    ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
	int i, hlen = ntohs(hwph->hw_addrlen);

	printf("hw_src_addr=");
	for (i = 0; i < hlen-1; i++)
	        printf("%02x:", hwph->hw_addr[i]);
	printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
	printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
	printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
	printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
	printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
	printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
	printf("payload_len=%d ", ret);

    fputc('\n', stdout);

    return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    printf("entering callback\n");
    
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
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    int tid = (int)data;

    t_printf(tid, "opening library handle\n");
    h = nfq_open();
    if (!h) {
	t_printf(tid, "error during nfq_open()\n");
	exit(1);
    }

    t_printf(tid, "unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
	t_printf(tid, "error during nfq_unbind_pf()\n");
	exit(1);
    }

    t_printf(tid, "binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
	t_printf(tid, "error during nfq_bind_pf()\n");
	exit(1);
    }

    t_printf(tid, "binding this socket to queue '%d'\n", tid);
    qh = nfq_create_queue(h, tid, &cb, NULL);
    if (!qh) {
	t_printf(tid, "error during nfq_create_queue()\n");
	exit(1);
    }

    t_printf(tid, "setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
	t_printf(tid, "can't set packet_copy mode\n");
	exit(1);
    }

    fd = nfq_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
	t_printf(tid, "pkt received\n");
	
	pthread_mutex_lock(&mutex_pt);
	nfq_handle_packet(h, buf, rv);
	pthread_mutex_unlock(&mutex_c);
	pthread_mutex_unlock(&mutex_pt);
    }

    t_printf(tid, "unbinding from queue %d\n", tid);
    nfq_destroy_queue(qh);

    t_printf(tid, "closing library handle\n");
    nfq_close(h);

    pthread_exit(NULL);
    return NULL;
}

int main(int argc, char **argv)
{
    int num_queues = 3;
    pthread_t threads[num_queues];
    int rc;
    void *status;

    pthread_mutex_init(&mutex_c, NULL);
    pthread_mutex_init(&mutex_pt, NULL);
    
    int i = 0;
    for (i = 0; i < num_queues; i++) {
	printf("Main: creating thread %d\n", i);
	rc = pthread_create(&threads[i], NULL, process_thread, (void *)i);

	if (rc) {
	    printf("ERROR; return code from pthread_create() is %d\n", rc);
	    exit(1);
	}
    }

    for (i = 0; i < num_queues; i++) {
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
