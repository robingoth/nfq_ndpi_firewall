#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "rule_helper.h"


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
	
	rule_set(conn, id, argv[4], argv[5], (unsigned short)atoi(argv[6]), argv[7], argv[8]);
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
