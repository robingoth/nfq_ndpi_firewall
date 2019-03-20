#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>

int update_label(int src_ip, int dst_ip, unsigned short src_port, unsigned short dst_port,
    int master_proto_id, int app_proto_id, int l4_proto)
{
  struct nfct_bitmask *bitmask;

  int ret;
  struct nfct_handle *h;
  struct nf_conntrack *ct;

  ct = nfct_new();
  if (!ct) {
    perror("nfct_new\n");
    return -1;
  }

  h = nfct_open(CONNTRACK, 0);
  if (!h) {
    perror("nfct_open\n");
    nfct_destroy(ct);
    return -1;
  }

  nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
  nfct_set_attr_u32(ct, ATTR_IPV4_SRC, src_ip);
  nfct_set_attr_u32(ct, ATTR_IPV4_DST, dst_ip);

  nfct_set_attr_u8(ct, ATTR_L4PROTO, l4_proto);
  nfct_set_attr_u16(ct, ATTR_PORT_SRC, src_port);
  nfct_set_attr_u16(ct, ATTR_PORT_DST, dst_port);

  bitmask = nfct_bitmask_new(127);
  nfct_bitmask_set_bit(bitmask, master_proto_id);
  nfct_bitmask_set_bit(bitmask, app_proto_id);
  nfct_bitmask_set_bit(bitmask, 0);
  nfct_set_attr(ct, ATTR_CONNLABELS, bitmask);

  ret = nfct_query(h, NFCT_Q_UPDATE, ct);

  nfct_close(h);
  nfct_destroy(ct);

  return ret;
}
