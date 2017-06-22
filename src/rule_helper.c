#include <assert.h>
#include <errno.h>
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

void rule_print(struct Rule *rule)
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

    printf("%s %s:%d %s '%s'\n", rule->src, rule->dst, rule->dport, rule->app, policy);
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
	struct Rule rule = { .id = i, .set = 0 };
	conn->rules->rules[i] = rule;
    }
}

void rule_set(struct Connection *conn, int id, const char *src, 
		const char *dst, const unsigned short dport, const char *app, const int policy)
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
    
    // set app
    res = strncpy(rule->app, app, MAX_DATA);
    rule->app[sizeof(rule->app) - 1] = '\0';

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
	rule_print(rule);
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
    struct Rule rule = { .id = id, .set = 0  };
    conn->rules->rules[id] = rule;
}

void rules_list(struct Connection *conn)
{
    int i = 0;
    struct Rules *rules = conn->rules;

    for (i = 0; i < MAX_RULES; i++) {
	struct Rule *cur = &rules->rules[i];

	if (cur->set) {
	    rule_print(cur);
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
		if ((strcmp(master_proto, rule->app) == 0) || 
			(strcmp(app_proto, rule->app) == 0) || 
			(strcmp(rule->app, any) == 0)) {
		    ret = 1;
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
