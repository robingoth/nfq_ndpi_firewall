#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "rule_helper.h"

char *ip_pattern = "\\d+\\.\\d+\\.\\d+\\.\\d+";
char *proto_pattern = "(.+)\\.(.+)";

int validate_inputs(char *proto, char *src, char *dst, char *policy)
{
    if (parse_string(proto, proto_pattern, 1) == NULL) {
	printf("ERROR: protocol is invalid. Acceptable format = master_proto.app_proto.\n");
	return 0;
    } 
    
    if ((parse_string(src, ip_pattern, 0) == NULL) && (strcmp(src, "any") != 0)) {
        printf("ERROR: '%s' IP is invalid.\n", src);
	return 0;
    }
    
    if ((parse_string(dst, ip_pattern, 0) == NULL) && (strcmp(dst, "any") != 0)) {
        printf("ERROR: '%s' IP is invalid.\n", dst);
	return 0;
    }
    
    if (set_policy(policy) == 0) {
        printf ("%s is an invalid policy.\n", policy);
	return 0;
    }

    return 1;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
	printf("USAGE: RuleManager <rulesfile> <action> [action params]\n");
	exit(1);
    }
    
    int are_valid;
    
    char *filename = argv[1];
    char action = argv[2][0];
    struct Connection *conn = rules_open(filename, action);
    
    unsigned short dport;
    int policy;
    char *src, *dst, *proto_str, *policy_str;
    const char *master_proto, *app_proto;
    const char **proto;

    int id = 0;
    
    switch(action) {
	case 'A':
	if (argc != 8) {
	    die("Need src, dst, dport, app and policy to append.", conn);
	}

	id = get_rules_num(conn);

	if (id >= MAX_RULES) {
	    die("Maximum number of rules has been reached, exiting.", conn);
	}
		
	src = argv[3];
	dst = argv[4];
	dport = (unsigned short)atoi(argv[5]);
	proto_str = argv[6];
	policy_str = argv[7];

	are_valid = validate_inputs(proto_str, src, dst, policy_str);
	if (are_valid == 0) {
	    die("One of the inputs was incorrect.", conn);
	}
	
	proto = parse_string(proto_str, proto_pattern, 1);
	master_proto = proto[1];
	app_proto = proto[2];

	policy = set_policy(policy_str);

	rule_set(conn, id, src, dst, dport, master_proto, app_proto, policy);
	rules_write(conn);
	break;
    case 'c':
	    rules_create(conn);
	    rules_write(conn);
	    break;
    case 'd':
	if (argc != 4) {
	    die("Need id to delete.", conn);
	}
    
	id = atoi(argv[3]);
	if (id >= MAX_RULES) {
	    die("There's not so many records.", conn);
	}
	
	rule_delete(conn, id);
	rules_write(conn);
	break;
    case 'g':
	if (argc != 4) {
	    die("Need an id to get.", conn);
	}
    
	id = atoi(argv[3]);
	if (id >= MAX_RULES) {
	    die("There's not so many records.", conn);
	}

	rule_get(conn, id);
	break;
    case 'I':
	if (argc == 8) {
	    id = 0;
	    src = argv[3];
	    dst = argv[4];
	    dport = (unsigned short)atoi(argv[5]);
	    proto_str = argv[6];
	    policy_str = argv[7];
	} else if (argc == 9) {
	    id = atoi(argv[3]);
	    if (id >= MAX_RULES) {
		die("There's not so many records.", conn);
	    }
	    
	    src = argv[4];
	    dst = argv[5];
	    dport = (unsigned short)atoi(argv[6]);
	    proto_str = argv[7];
	    policy_str = argv[8];
	} else {
	    die("Need [id], src, dst, dport, app, policy to insert.", conn);
	}

	are_valid = validate_inputs(proto_str, src, dst, policy_str);
	if (are_valid == 0) {
	    die("One of the inputs was incorrect.", conn);
	}

	proto = parse_string(proto_str, proto_pattern, 1);
	master_proto = proto[1];
	app_proto = proto[2];

	policy = set_policy(policy_str);

	int num_of_rules = get_rules_num(conn);
	if (num_of_rules >= MAX_RULES) {
	    die("Maximum number of rules reached.", conn);
	}

	// create temporary storage for rules
	struct Rules *rules = malloc(sizeof(*rules));
	int q = 0;
	for (q = 0; q < MAX_RULES; q++) {
	    struct Rule rule = { .set = 0 };
	    rules->rules[q] = rule;
	}

	// copy rules before id as is
	for (q = 0; q < id; q++) {
	    rules->rules[q] = conn->rules->rules[q];
	}
	
	// copy rules after id with updated ids
	for (q = num_of_rules; q > id; q--) {
	    rules->rules[q] = conn->rules->rules[q - 1];
	}
	
	// copy new rule
	rules->rules[id].set = 1;
	
	// set src
	char *res = strncpy(rules->rules[id].src, src, strlen(src)); // 16 is the IP address + \0
	rules->rules[id].src[sizeof(rules->rules[id].src) - 1] = '\0';
        
	if (!res) {
	    die("Source copy failed.", conn);
        }
        
	// set dst
        res = strncpy(rules->rules[id].dst, dst, strlen(dst));
        rules->rules[id].dst[sizeof(rules->rules[id].dst) - 1] = '\0';
        
	if (!res) {
	    die("Destination copy failed.", conn);
        }
        
	// set dport
        rules->rules[id].dport = dport;
        
	// set master_proto
        res = strncpy(rules->rules[id].master_proto, master_proto, MAX_DATA);
        rules->rules[id].master_proto[sizeof(rules->rules[id].master_proto) - 1] = '\0';
	
	// set app_proto
        res = strncpy(rules->rules[id].app_proto, app_proto, MAX_DATA);
        rules->rules[id].app_proto[sizeof(rules->rules[id].app_proto) - 1] = '\0';
        
	if (!res) {
	    die("Application copy failed.", conn);
        }
        
	//set policy
        rules->rules[id].policy = policy;

	conn->rules = rules;
	
	rules_write(conn);
	break;
    case 'l':
	rules_list(conn);
	break;
    case 's':
	if (argc != 9) {
	    die("Need id, src, dst, dport, app and policy to set.", conn);
	}
	
	id = atoi(argv[3]);
	if (id >= MAX_RULES) {
	    die("There's not so many records.", conn);
	}
	
	src = argv[4];
	dst = argv[5];
	dport = (unsigned short)atoi(argv[6]);
	proto_str = argv[7];
	policy_str = argv[8];

	are_valid = validate_inputs(proto_str, src, dst, policy_str);
	if (are_valid == 0) {
	    die("One of the inputs was incorrect.", conn);
	}

	proto = parse_string(proto_str, proto_pattern, 1);
	master_proto = proto[1];
	app_proto = proto[2];

	policy = set_policy(policy_str);

	rule_set(conn, id, src, dst, dport, master_proto, app_proto, policy);
	rules_write(conn);
	break;
    default:
	die("Invalid action: A=append, c=create, d=delete, g=get, I=insert, l=list, s=set", conn);
    }
    
    rules_close(conn);
    return 0;
}
