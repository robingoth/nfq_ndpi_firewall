#ifndef CONNTRACK_HELPER_H_
#define CONNTRACK_HELPER_H_

int update_label(int src_ip, int dst_ip, unsigned short src_port, unsigned short dst_port, int master_proto_id, int app_proto_id, int proto_type);

#endif // CONNTRACK_HELPER_H_
