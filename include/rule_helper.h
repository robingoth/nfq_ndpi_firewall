#define MAX_RULES 100
#define MAX_DATA 512

// Preprocessor directives
#define ALLOW           100
#define DENY            200
#define REJECT          300
#define ALLOW_WITH_IPS  400

// Structs
struct Rule {
    int set;
    char src[16];
    char dst[16];
    unsigned short dport;
    char app[MAX_DATA];
    int policy;
};

struct Rules {
    struct Rule rules[MAX_RULES];
};

struct Connection {
    FILE *file;
    struct Rules *rules;
};

void die(const char *message, struct Connection *conn);

void rule_print(struct Rule *rule, int id);

void rules_load(struct Connection *conn);

struct Connection *rules_open(const char *filename, char mode);

void rules_close(struct Connection *conn);

void rules_write(struct Connection *conn);

void rules_create(struct Connection *conn);

void rule_set(struct Connection *conn, int id, const char *src,
	const char *dst, const unsigned short dport, const char *app, const int policy);

void rule_get(struct Connection *conn, int id);

struct Rules *rules_get(struct Connection *conn);

void rule_delete(struct Connection *conn, int id);

void rules_list(struct Connection *conn);

int is_match(struct Rule *rule, char *src, char *dst, unsigned short dport,
		char *master_proto, char *app_proto);

int get_rules_num(struct Connection *conn);

int set_policy(char *policy_str);
