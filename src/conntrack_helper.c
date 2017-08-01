#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>

int update_label(char *src_ip, char *dst_ip, unsigned short src_port, unsigned short dst_port, 
		    int master_proto_id, int app_proto_id)
{
    struct nfct_bitmask *a;

    int ret;
    struct nfct_handle *h;
    struct nf_conntrack *ct;

    ct = nfct_new();
    if (!ct) {
	perror("nfct_new\n");
	return 0;
    }

    nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
    nfct_set_attr_u32(ct, ATTR_IPV4_SRC, inet_addr(src_ip));
    nfct_set_attr_u32(ct, ATTR_IPV4_DST, inet_addr(dst_ip));

    nfct_set_attr_u8(ct, ATTR_L4PROTO, IPPROTO_TCP);
    nfct_set_attr_u16(ct, ATTR_PORT_SRC, htons(src_port));
    nfct_set_attr_u16(ct, ATTR_PORT_DST, htons(dst_port));

    nfct_setobjopt(ct, NFCT_SOPT_SETUP_REPLY);

    a = nfct_bitmask_new(127);
    nfct_bitmask_set_bit(a, master_proto_id);
    nfct_bitmask_set_bit(a, app_proto_id);
    nfct_set_attr(ct, ATTR_CONNLABELS, a);

    h = nfct_open(CONNTRACK, 0);
    if (!h) {
	perror("nfct_open\n");
	nfct_destroy(ct);
	return -1;
    }

    ret = nfct_query(h, NFCT_Q_UPDATE, ct);

    /*
    if (ret == -1)
	printf("(%d)(%s)\n", ret, strerror(errno));
    else
	printf("(OK)\n");
    */

    nfct_close(h);

    nfct_destroy(ct);

    return ret;
}
