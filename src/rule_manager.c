#include <pcre.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "rule_helper.h"

const char *ip_pattern = "(\\d+)\\.(\\d+)\\.(\\d+)\\.(\\d+)";

int validate_ip_string(char *string)
{
    if (strcmp(string, "any") == 0) {
	return 1;
    }

    pcre *re_compiled;
    pcre_extra *pcre_ex;
    const char pcre_error_str;
    int pcre_error_offset;
    int pcre_exec_ret;
    int sub_str_vec[30];

    int ret = 0;

    re_compiled = pcre_compile(ip_pattern, 0, &pcre_error_str, &pcre_error_offset, NULL);

    if (re_compiled == NULL) {
	printf("ERROR: could not compile '%s': %s\n", ip_pattern, pcre_error_str);
	exit(1);
    }

    pcre_ex = pcre_study(re_compiled, 0, &pcre_error_str);
    if (pcre_error_str != NULL) {
	printf("ERROR: Could not study '%s': %s\n", ip_pattern, pcre_error_str);
    }

    pcre_exec_ret = pcre_exec(re_compiled, pcre_ex, string, strlen(string), 0, 0, sub_str_vec, 30);

    if (pcre_exec_ret > 0) {
	ret = 1;
    }

    return ret;
}

int set_policy(char *policy_str)
{
    int result;
        
    if (strcmp(policy_str, "ALLOW") == 0) {
        result = ALLOW;
    } else if (strcmp(policy_str, "DENY") == 0) {
	result = DENY;
    } else if (strcmp(policy_str, "REJECT") == 0) {
	result = REJECT;
    } else if (strcmp(policy_str, "ALLOW with IPS") == 0) {
	result = ALLOW_WITH_IPS; 
    } else {
	printf ("%s is an invalid policy.\n", policy_str);
	printf("Valid options are: 'ALLOW', 'DENY', 'REJECT', 'ALLOW with IPS'.\n");
	exit(1);
    }

    return result;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
	printf("USAGE: RuleManager <rulesfile> <action> [action params]\n");
	exit(1);
    }
    
    char *filename = argv[1];
    char action = argv[2][0];
    struct Connection *conn = rules_open(filename, action);
    
    unsigned short dport;
    int policy;
    char *src, *dst, *app, *policy_str;

    int id = 0;
    if (argc > 3) {
	id = atoi(argv[3]);
    }
    
    if (id >= MAX_RULES) {
	die("There's not so many records.", conn);
    }
    
    switch(action) {
	case 'A':
	if (argc != 8) {
	    die("Need src, dst, dport, app and policy to append.", conn);
	}

	id = get_rules_num(conn);

	if (id >= MAX_RULES) {
	    printf("Maximum number of rules has been reached, exiting.\n");
	    exit(1);
	}
		
	src = argv[3];
	dst = argv[4];
	dport = (unsigned short)atoi(argv[5]);
	app = argv[6];
	policy_str = argv[7];

	if (validate_ip_string(src) == 0) {
	    printf("ERROR: '%s' ip is invalid.\n", src);
	    exit(1);
	}

	if (validate_ip_string(dst) == 0) {
		printf("ERROR: '%s' ip is invalid.\n", dst);
		exit(1);
	}

	policy = set_policy(policy_str);

	rule_set(conn, id, src, dst, dport, app, policy);
	rules_write(conn);
	break;
    case 'c':
	    rules_create(conn);
	    rules_write(conn);
	    break;
    case 'g':
	if (argc != 4) {
	    die("Need an id to get.", conn);
	}
    
	rule_get(conn, id);
	break;
    case 's':
	if (argc != 9) {
	    die("Need id, src, dst, dport, app and policy to set.", conn);
	}
	
	src = argv[4];
	dst = argv[5];
	dport = (unsigned short)atoi(argv[6]);
	app = argv[7];
	policy_str = argv[8];

	if (validate_ip_string(src) == 0) {
	    printf("ERROR: '%s' ip is invalid.\n", src);
	    exit(1);
	}

	if (validate_ip_string(dst) == 0) {
		printf("ERROR: '%s' ip is invalid.\n", dst);
		exit(1);
	}

	policy = set_policy(policy_str);

	rule_set(conn, id, src, dst, dport, app, policy);
	rules_write(conn);
	break;
    case 'd':
	if (argc != 4) {
	    die("Need id to delete.", conn);
	}
    
	rule_delete(conn, id);
	rules_write(conn);
	break;
    case 'l':
	rules_list(conn);
	break;
    default:
	die("Invalid action: c=create, g=get, s=set, d=del, l=list", conn);
    }
    
    rules_close(conn);
    return 0;
}
