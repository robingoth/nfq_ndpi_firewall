#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <json-c/json.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnfnetlink/linux_nfnetlink.h>

#include "ndpi_helper.h"

#define VERSION "2.0"
#define BUFFERSIZE 65535
#define MAX_NUM_QUEUES 10

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
static char *QueueNum[MAX_NUM_QUEUES];
int QueueSize               = 0;
int NumRoots                = 512; 
int MaxFlows                = 200000000;
int IdleScanPeriod          = 100; 
int MaxIdleTime             = 30000; 
int MaxIdleFlows            = 1024;
int Errors                  = 0;
static u_int8_t Verbose     = 0;
/** User preferences **/
u_int8_t enable_protocol_guess = 1;

void t_printf(int tid, char *format, ...);

/**
 * From IPPROTO to string NAME
 */
static char* ipProto2Name(u_int16_t proto_id) {
  static char proto[8];

  switch(proto_id) {
    case IPPROTO_TCP:
      return("TCP");
      break;
    case IPPROTO_UDP:
      return("UDP");
      break;
    case IPPROTO_ICMP:
      return("ICMP");
      break;
    case IPPROTO_ICMPV6:
      return("ICMPV6");
      break;
    case 112:
      return("VRRP");
      break;
    case IPPROTO_IGMP:
      return("IGMP");
      break;
  }

  snprintf(proto, sizeof(proto), "%u", proto_id);
  return(proto);
}

void printFlow(int tid, struct ndpi_proto proto, struct ndpi_detection_module_struct *ndpi_struct, struct flow_info *flow){
  json_object *jObj = json_object_new_object();

  // QUEUE
  json_object_object_add(jObj, "queue", json_object_new_int(tid));

  // PROTOCOL APPLICATION
  char *proto_base; // e.g. HTTP
  char *proto_app; // e.g. Facebook
  proto_base = ndpi_get_proto_name(ndpi_struct, proto.master_protocol);
  proto_app = ndpi_get_proto_name(ndpi_struct, proto.app_protocol);
  //int proto_app_id = ndpi_get_protocol_id(ndpi_struct, proto_app);
  if(proto.master_protocol) {
    char buf[64];
    json_object_object_add(jObj, "proto.full-name", json_object_new_string(ndpi_protocol2name(ndpi_struct, proto, buf, sizeof(buf))));
  } else
    json_object_object_add(jObj, "proto.full-name", json_object_new_string(proto_app));

  json_object_object_add(jObj, "proto.master-name", json_object_new_string(proto_base));
  json_object_object_add(jObj, "proto.app-name", json_object_new_string(proto_app));
  json_object_object_add(jObj, "proto.app-id", json_object_new_int(proto.app_protocol));
  json_object_object_add(jObj, "proto.master-id", json_object_new_int(proto.master_protocol));

  // BREED
  ndpi_protocol_breed_t breed = ndpi_get_proto_breed(ndpi_struct, proto.app_protocol);
  json_object_object_add(jObj, "proto.breed", json_object_new_string(ndpi_get_proto_breed_name(ndpi_struct, breed)));

  // CATEGORY
  if(proto.category != 0){
    json_object_object_add(jObj, "proto.category-name", json_object_new_string(ndpi_category_get_name(ndpi_struct, proto.category)));
    json_object_object_add(jObj, "proto.category-id", json_object_new_int((unsigned int)proto.category));
  } else {
    json_object_object_add(jObj, "proto.category-name", json_object_new_string(""));
    json_object_object_add(jObj, "proto.category-id", json_object_new_int(0));
  }

  // URL DATA
  json_object_object_add(jObj, "http.url", json_object_new_string(ndpi_get_http_url(ndpi_struct, flow->ndpi_flow)));
  json_object_object_add(jObj, "http.content-type", json_object_new_string(ndpi_get_http_content_type(ndpi_struct, flow->ndpi_flow)));

  // NETWORK DATA
  u_int16_t sport, dport;
  char *l4_protocol_name = ipProto2Name(flow->protocol);
  if (strcmp(l4_protocol_name, "TCP") == 0 || strcmp(l4_protocol_name, "UDP") == 0){
    sport = ntohs(flow->src_port), dport = ntohs(flow->dst_port);
  } else {
    // non tcp/udp protocols
    sport = dport = 0;
  }
  json_object_object_add(jObj, "net.protocol", json_object_new_string(l4_protocol_name));

  char src_ip_name[48];
  char dst_ip_name[48];
  //if(flow->ip_version == IPVERSION) //TODO
    inet_ntop(AF_INET, &(flow->src_ip), src_ip_name, sizeof(src_ip_name));
    inet_ntop(AF_INET, &(flow->dst_ip), dst_ip_name, sizeof(dst_ip_name));
  //else
  //  inet_ntop(AF_INET6, &(flow->src_ip),  addr_name, sizeof(addr_name));
  json_object_object_add(jObj, "net.src-ip", json_object_new_string(src_ip_name));
  json_object_object_add(jObj, "net.src-port", json_object_new_int(sport));
  json_object_object_add(jObj, "net.dst-ip", json_object_new_string(dst_ip_name));
  json_object_object_add(jObj, "net.dst-port", json_object_new_int(dport));

  // GUESS PROTOCOL APPLICATION
  proto = ndpi_guess_undetected_protocol(ndpi_struct, flow->ndpi_flow, flow->protocol, ntohl(flow->src_ip), ntohs(flow->src_port), ntohl(flow->dst_ip), ntohs(flow->dst_port));
  proto_base = ndpi_get_proto_name(ndpi_struct, proto.master_protocol);
  proto_app = ndpi_get_proto_name(ndpi_struct, proto.app_protocol);
  if(proto.master_protocol) {
    char buf[64];
    json_object_object_add(jObj, "proto-guess.full-name", json_object_new_string(ndpi_protocol2name(ndpi_struct, proto, buf, sizeof(buf))));
  } else
    json_object_object_add(jObj, "proto-guess.full-name", json_object_new_string(proto_app));
  json_object_object_add(jObj, "proto-guess.master-name", json_object_new_string(proto_base));
  json_object_object_add(jObj, "proto-guess.app-name", json_object_new_string(proto_app));
  json_object_object_add(jObj, "proto-guess.app-id", json_object_new_int(proto.app_protocol));
  json_object_object_add(jObj, "proto-guess.master-id", json_object_new_int(proto.master_protocol));

  ////
  if (Verbose > 1) printf("%s\n", json_object_to_json_string(jObj));

  json_object_put(jObj);// free
}

/*
 * Callback function called for each packet 
 */
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
  // read thread-specific data
  struct q_data *t_data = (struct q_data *)data;

  int id;
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

  unsigned char *packet_data;
  unsigned short payload_size;
  payload_size = nfq_get_payload(nfa, &packet_data);

  if (payload_size == -1) {
    t_printf(t_data->id, "Packet payload was not retrieved. Skipping current packet.\n");
    return -1;
  }

  struct flow_info *flow;
  flow = detect_protocol(packet_data, payload_size, tv, t_data->workflow);


  struct ndpi_proto proto;
  proto = flow->detected_protocol;

  printFlow(t_data->id, proto, t_data->workflow->ndpi_struct, flow);// PRINT

  // free idle flows
  t_data->workflow->timestamp = ((uint64_t) tv.tv_sec) * TICK_RESOLUTION + 
    tv.tv_usec / (1000000 / TICK_RESOLUTION);
  if (t_data->workflow->last_idle_scan + IdleScanPeriod < t_data->workflow->timestamp) {
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
void t_printf(int tid, char *format, ...){
  if (!Verbose)
    return;

  va_list ap;
  va_start(ap, format);
  printf("Queue %d: ", tid);
  vfprintf(stdout, format, ap);
  va_end(ap);
}

void *process_thread(void *data){
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

  t_printf(t_data->id, "setting buffer size to %d\n", BUFFERSIZE);
  nfnl_rcvbufsiz(t_data->nh, BUFFERSIZE);

  // set socket option NETLINK_NO_ENOBUFS for performance improvement
  opt = 1;
  if (setsockopt(t_data->sockfd, SOL_NETLINK, NETLINK_NO_ENOBUFS, 
        &opt, sizeof(int)) == -1) {
    printf("ERROR: Can't set netlink enobufs: %s", strerror(errno));
    exit(1);
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
        break; /* No error, just netlink closed. Drop out. */
      }

      if (rv == (ssize_t)-1) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
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

void print_setup(){
  if (!Verbose)
    return;

  printf("Configuration of this run is the following:\n");
  printf("\tnumber of queues \t %d\n", QueueSize);
  printf("\tnumber of roots \t %d\n", NumRoots);
  printf("\tmaximum flows \t\t %d\n", MaxFlows);
  printf("\tidle scan period \t %d\n", IdleScanPeriod);
  printf("\tmaximum idle time \t %d\n", MaxIdleTime);
  printf("\tmaximum idle flows \t %d\n", MaxIdleFlows);
  printf("\tverbose \t\t %d\n", Verbose);
  printf("\n");
}

static void printVersion(){
  printf("Welcome to nfdpi %s with nDPI %s.\n", VERSION, ndpi_revision());
}

/**
 * Print help instructions
 */
static void help(u_int long_help) {
  printVersion();

  printf("\nnfdpi -q <queue num> -q <queue num>\n\n"
   "Usage:\n"
   "  -q <queue num>            | Specify a number of queue to read packets from. Example -q 10 -q 11 -q 30. Limited in 10 queues.\n"
   "  -r <num roots>            | Number of roots of a binary tree. Default: 512.\n"
   "  -f <max flows>            | Maximum number of flows. Default: 200000000.\n"
   "  -i <num ms>               | Time period in milliseconds of scans for idle flows. Default: 100 ms.\n"
   "  -t <num ms>               | Maximum amount of time in milliseconds a flow can be idle. Default: 30000 ms.\n"
   "  -F <num idle flows>       | Maximum number of idle flows. Default: 1024.\n"
   "  -v <1|2>                  | Verbose.\n"
   "                            | 1 = verbose\n"
   "                            | 2 = very verbose\n"
   "  -v                        | Display version.\n"
   "  -h                        | Display this help.\n");

  exit(!long_help);
}

static struct option longopts[] = {
  { "enable-protocol-guess", no_argument, NULL, 'd'},
  { "queue",                 required_argument, NULL, 'q'},
  { "num-roots",             required_argument, NULL, 'r'},
  { "max-idle-flows",        required_argument, NULL, 'F'},
  { "max-flows",             required_argument, NULL, 'f'},
  { "idle-scan-period",      required_argument, NULL, 'i'},
  { "max-idle-time",         required_argument, NULL, 't'},
  { "verbose",               required_argument, NULL, 'v'},
  { "version",               no_argument, NULL, 'V'},
  { "help",                  no_argument, NULL, 'h'},
  { 0,                       0,           0,     0}
};

/**
 * Option parser
 */
static void parseOptions(int argc, char **argv) {
  int option_idx = 0;//, do_capture = 0;
  int opt;
  char* endptr;

  while((opt = getopt_long(argc, argv, "dq:r:F:f:i:t:v:Vh", longopts, &option_idx)) != EOF) {
    switch (opt) {
      case 'd':
        enable_protocol_guess = 0;
        break;
      case 'q':
        QueueNum[QueueSize++] = optarg;
        break;
      case 'r':
        NumRoots = strtoimax(optarg, &endptr, 10);
        break;
      case 'F':
        MaxIdleFlows = strtoimax(optarg, &endptr, 10);
        break;
      case 'f':
        MaxFlows = strtoimax(optarg, &endptr, 10);
        break;
      case 'i':
        IdleScanPeriod = strtoimax(optarg, &endptr, 10);
        break;
      case 't':
        MaxIdleTime = strtoimax(optarg, &endptr, 10);
        break;
      case 'v':
        Verbose = strtoimax(optarg, &endptr, 10);
        break;
      case 'V':
        printVersion();
        exit(0);
        break;
      case 'h':
        help(1);
        break;
      default:
        help(0);
        break;
    }
  }

  // check parameters
  if(QueueNum[0] == NULL || strcmp(QueueNum[0], "") == 0 || QueueSize > MAX_NUM_QUEUES) {
    help(1);
  }
  if (MaxIdleFlows <= 0){
    printf("Error: max-idle-flows has not a valid value.\n\n");
    help(1);
  }
  if (MaxIdleTime <= 0){
    printf("Error: max-idle-time has not a valid value.\n\n");
    help(1);
  }
  if (IdleScanPeriod <= 0){
    printf("Error: idle-scan-period has not a valid value.\n\n");
    help(1);
  }
  if (MaxFlows <= 0){
    printf("Error: max-flows has not a valid value.\n\n");
    help(1);
  }
  if (NumRoots <= 0){
    printf("Error: num-roots has not a valid value.\n\n");
    help(1);
  }
}

int main(int argc, char **argv){

  parseOptions(argc, argv);

  int rc;
  void *status;

  print_setup();

  pthread_t threads[QueueSize];

  pthread_mutex_init(&mutex_c, NULL);
  pthread_mutex_init(&mutex_pt, NULL);

  struct q_data data[QueueSize];

  int i = 0;
  // prepare data for each thread
  for (i = 0; i < QueueSize; i++) {
    data[i].id = atoi(QueueNum[i]);

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

    workflow->max_idle_flows = MaxIdleFlows;
    workflow->idle_flows = ndpi_calloc(MaxIdleFlows, sizeof(struct flow_info *));
    if (workflow->idle_flows == NULL) {
      printf("ERROR: idle_flows initialization failed");
      exit(1);
    }

    workflow->ndpi_struct = setup_detection();

    data[i].workflow = workflow;
  }

  // create threads
  for (i = 0; i < QueueSize; i++) {
    if (Verbose) printf("Main: creating thread %d\n", i);

    rc = pthread_create(&threads[i], NULL, process_thread, &data[i]);

    if (rc) {
      printf("ERROR; return code from pthread_create() is %d\n", rc);
      exit(1);
    }
  }

  for (i = 0; i < QueueSize; i++) {
    rc = pthread_join(threads[i], &status);
    if (rc) {
      printf("ERROR; return code from pthread_join() is %d\n", rc);
      exit(1);
    }

    if (Verbose) printf("Main: completed join with thread %d having a status of %ld\n", i, (long)status);
  }

  if (Verbose) printf("Main: program completed. Exiting.\n");

  pthread_mutex_destroy(&mutex_c);
  pthread_mutex_destroy(&mutex_pt);
  pthread_exit(NULL);
  exit(0);
}
