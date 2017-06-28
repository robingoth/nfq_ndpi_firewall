#include <assert.h>
#include <errno.h>
#include <pcre.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rule_helper.h"

// Forward declarations
void rules_close(struct Connection *conn);

void die(const char *message, struct Connection *conn)
{
    if (errno) {
	perror(message);
    } else {
	printf("ERROR: %s\n", message);
    }

    rules_close(conn);
    exit(1);
}

void rule_print(struct Rule *rule, int id)
{
    char *policy;
    switch (rule->policy) {
	case ALLOW:
	    policy = "ALLOW";
	    break;
	case DENY:
	    policy = "DENY";
	    break;
	case REJECT:
	    policy = "REJECT";
	    break;
	case ALLOW_WITH_IPS:
	    policy = "ALLOW with IPS";
	    break;
	default:
	    printf("ERROR: rule print failed.\n");
	    exit(1);
    }

    printf("%d -> %s %s:%d %s.%s '%s'\n", id, rule->src, rule->dst, rule->dport, 
	    rule->master_proto, rule->app_proto, policy);
}

void rules_load(struct Connection *conn) 
{
    int rc = fread(conn->rules, sizeof(struct Rules), 1, conn->file);

    if (rc != 1) {
	die("Failed to load rules.", conn);
    }
}

struct Connection *rules_open(const char *filename, char mode)
{
    struct Connection *conn = malloc(sizeof(struct Connection));

    if (!conn) {
	die("Memory error", conn);
    }

    conn->rules = malloc(sizeof(struct Rules));

    if (!conn->rules) {
	die("Memory error", conn);
    }

    if (mode == 'c') {
	conn->file = fopen(filename, "w");
    } else {
	conn->file = fopen(filename, "r+");

	if (conn->file) {
	    rules_load(conn);
	}
    }

    if (!conn->file) {
	die("Failed to open the file", conn);
    }

    return conn;
}

void rules_close(struct Connection *conn)
{
    if (conn) {
	if (conn->file) {
	    fclose(conn->file);
	}

	if (conn->rules) {
	    free(conn->rules);
	}

	free(conn);
    }
}

void rules_write(struct Connection *conn)
{
    rewind(conn->file);

    int rc = fwrite(conn->rules, sizeof(struct Rules), 1, conn->file);

    if (rc != 1) {
	die("Failed to write rules.", conn);
    }

    rc = fflush(conn->file);

    if (rc == -1) {
	die("Cannot flush rules.", conn);
    }
}

void rules_create(struct Connection *conn)
{
    int i = 0;
    for (i = 0; i < MAX_RULES; i++) {
	struct Rule rule = { .set = 0 };
	conn->rules->rules[i] = rule;
    }
}

void rule_set(struct Connection *conn, int id, const char *src, 
		const char *dst, const unsigned short dport, const char *master_proto, 
		const char *app_proto, const int policy)
{
    struct Rule *rule = &conn->rules->rules[id];
        
    if (rule->set) {
	die("Already set, delete it first", conn);
    }

    rule->set = 1;

    // set src
    char *res = strncpy(rule->src, src, strlen(src)); // 16 is the IP address + \0
    rule->src[sizeof(rule->src) - 1] = '\0';

    if (!res) {
	die("Source copy failed.", conn);
    }   

    // set dst
    res = strncpy(rule->dst, dst, strlen(dst));
    rule->dst[sizeof(rule->dst) - 1] = '\0';

    if (!res) {
	die("Destination copy failed.", conn);
    }   
    
    // set dport
    rule->dport = dport;
    
    // set master_proto
    res = strncpy(rule->master_proto, master_proto, MAX_DATA);
    rule->master_proto[sizeof(rule->master_proto) - 1] = '\0';

    // set app_proto
    res = strncpy(rule->app_proto, app_proto, MAX_DATA);
    rule->app_proto[sizeof(rule->app_proto) - 1] = '\0';

    if (!res) {
	die("Application copy failed.", conn);
    }   
    
    //set policy
    rule->policy = policy;
}

void rule_get(struct Connection *conn, int id) 
{
    struct Rule *rule = &conn->rules->rules[id];

    if (rule->set) {
	rule_print(rule, id);
    } else {
	die("ID not set.", conn);
    }
}

struct Rules *rules_get(struct Connection *conn)
{
    struct Rules *rules = conn->rules;
    
    if (rules) {
	return rules;
    } else {
	return NULL;
    }
}

void rule_delete(struct Connection *conn, int id) 
{
    // create temporary storage for rules
    struct Rules *new_rules = malloc(sizeof(*new_rules));
    int i = 0;
    for (i = 0; i < MAX_RULES; i++) {
	struct Rule rule = { .set = 0 };
	new_rules->rules[i] = rule;
    }

    for (i = 0; i < id; i++) {
	new_rules->rules[i] = conn->rules->rules[i];
    }

    for (i = id; i < MAX_RULES - 1; i++) {
	new_rules->rules[i] = conn->rules->rules[i + 1];
    }

    conn->rules = new_rules;
}

void rules_list(struct Connection *conn)
{
    int i = 0;
    struct Rules *rules = conn->rules;

    for (i = 0; i < MAX_RULES; i++) {
	struct Rule *cur = &rules->rules[i];

	if (cur->set) {
	    rule_print(cur, i);
	}
    }
}

int is_match(struct Rule *rule, char *src, char *dst, unsigned short dport, 
		char *master_proto, char *app_proto)
{
    int ret = 0;
    char *any = "any";

    if ((strcmp(rule->src, src) == 0) || (strcmp(rule->src, any) == 0)) {
	if ((strcmp(rule->dst, dst) == 0) || (strcmp(rule->dst, any) == 0)) {
	    if ((rule->dport == dport) || (rule->dport == 0)) {
		if ((strcmp(rule->master_proto, master_proto) == 0) || 
			    (strcmp(rule->master_proto, any) == 0)) {
		    if ((strcmp(rule->app_proto, app_proto) == 0) || (strcmp(rule->app_proto, any) == 0)) {
			ret = 1;
		    }	
		}
	    }
	}
    }

    return ret;
}

int get_rules_num(struct Connection *conn)
{
    int res = 0;
    int i = 0;
    for (i = 0; i < MAX_RULES; i++) {
	struct Rule *cur = &conn->rules->rules[i];

	if (cur->set == 1) {
	    res++;
	}
    }

    return res;
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
	result = 0;
    }

    return result;
}

const char **parse_string(char *string, char *pattern, int debug)
{
    int ovector_len = 30;

    pcre *re;
    const char *error;
    int erroffset;
    int ovector[ovector_len];
    int rc;
    const char *subString;

    re = pcre_compile(pattern, 0, &error, &erroffset, NULL);

    if (re == NULL) {
	printf("ERROR: compilation failed at offset %d: '%s'\n", erroffset, error);
	return NULL;
    }

    rc = pcre_exec(re, NULL, string, strlen(string), 0, 0, ovector, ovector_len);

    if (rc < 0) {
	switch (rc) {
	    case PCRE_ERROR_NOMATCH:
		if (debug == 1) {
		    printf("%s did not match.\n", string);
		}
		break;
	    case PCRE_ERROR_NULL:
		printf("ERROR: Something was null.\n");
		break;
	    case PCRE_ERROR_BADOPTION:
		printf("ERROR: A bad option was passed.\n");
		break;
	    case PCRE_ERROR_BADMAGIC:
		printf("ERROR: Magic number was bad.\n");
		break;
	    case PCRE_ERROR_UNKNOWN_NODE:
		printf("ERROR: Something kooky in the compiled re.\n");
		break;
	    case PCRE_ERROR_NOMEMORY:
		printf("ERROR: Ran out of memory.\n");
		break;
	    default:
		printf("ERROR: Unknown error.\n");
	}

	pcre_free(re);
	return NULL;
    } else {
	const char **res = malloc(rc * sizeof(const char *));
	int i = 0;
	for (i = 0; i < rc; i++) {
	    res[i] = malloc(MAX_DATA * sizeof(const char));
	}

	for (i = 0; i < rc; i++) {
	    pcre_get_substring(string, ovector, rc, i, &(subString));
	    res[i] = subString;
	}
	return res;
    }
}
