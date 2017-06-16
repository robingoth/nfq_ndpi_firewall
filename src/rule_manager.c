#include <pcre.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "rule_helper.h"

int validate_ip_string(char *string, char *pattern)
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

    re_compiled = pcre_compile(pattern, 0, &pcre_error_str, &pcre_error_offset, NULL);

    if (re_compiled == NULL) {
	printf("ERROR: could not compile '%s': %s\n", pattern, pcre_error_str);
	exit(1);
    }

    pcre_ex = pcre_study(re_compiled, 0, &pcre_error_str);
    if (pcre_error_str != NULL) {
	printf("ERROR: Could not study '%s': %s\n", pattern, pcre_error_str);
    }

    pcre_exec_ret = pcre_exec(re_compiled, pcre_ex, string, strlen(string), 0, 0, sub_str_vec, 30);

    if (pcre_exec_ret > 0) {
	ret = 1;
    }

    return ret;
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
    
    int id = 0;
    if (argc > 3) {
	id = atoi(argv[3]);
    }
    
    if (id >= MAX_RULES) {
	die("There's not so many records.", conn);
    }
    
    switch(action) {
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
	
	unsigned short dport;
	int policy;
	char *src, *dst, *app, *policy_str;
	
	src = argv[4];
	dst = argv[5];
	dport = (unsigned short)atoi(argv[6]);
	app = argv[7];
	policy_str = argv[8];

	char *pattern = "(\\d+)\\.(\\d+)\\.(\\d+)\\.(\\d+)";

	if (validate_ip_string(src, pattern) == 0) {
	    printf("ERROR: '%s' ip is invalid.\n", src);
	    exit(1);
	}

	if (validate_ip_string(dst, pattern) == 0) {
		printf("ERROR: '%s' ip is invalid.\n", dst);
		exit(1);
	}

	if (strcmp(policy_str, "ALLOW") == 0) {
	    policy = ALLOW;
	} else if (strcmp(policy_str, "DENY") == 0) {
	    policy = DENY;
	} else if (strcmp(policy_str, "REJECT") == 0) {
	    policy = REJECT;
	} else if (strcmp(policy_str, "ALLOW with IPS") == 0) {
	   policy = ALLOW_WITH_IPS; 
	} else {
	    printf ("%s is an invalid policy.\n", policy_str);
	    printf("Valid options are: 'ALLOW', 'DENY', 'REJECT', 'ALLOW with IPS'.\n");
	    exit(1);
	}

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
