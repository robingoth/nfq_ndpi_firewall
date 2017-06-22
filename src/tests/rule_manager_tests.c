#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <cmocka.h>

#include "rule_helper.h"

/* Wrap functions */





/********************/

/* Tests */
static void set_policy_test_allow(void **state)
{
    (void) state; /* unused */
    int actual, expected;
    expected = ALLOW;

    char *policy_str = "ALLOW";
    actual = set_policy(policy_str);

    assert_int_equal(actual, expected);
}

static void set_policy_test_deny(void **state)
{
    (void) state; /* unused */
    int actual, expected;
    expected = DENY;

    char *policy_str = "DENY";
    actual = set_policy(policy_str);

    assert_int_equal(actual, expected);
}

static void set_policy_test_reject(void **state)
{
    (void) state; /* unused */
    int actual, expected;
    expected = REJECT;

    char *policy_str = "REJECT";
    actual = set_policy(policy_str);

    assert_int_equal(actual, expected);
}

static void set_policy_test_allow_ips(void **state)
{
    (void) state; /* unused */
    int actual, expected;
    expected = ALLOW_WITH_IPS;

    char *policy_str = "ALLOW with IPS";
    actual = set_policy(policy_str);

    assert_int_equal(actual, expected);
}

static void set_policy_test_invalid(void **state)
{
    (void) state; /* unused */
    int actual, expected;
    expected = 0;

    char *policy_str = "This is so wrong Carl";
    actual = set_policy(policy_str);

    assert_int_equal(actual, expected);
}

static void get_rules_num_test(void **state)
{
    (void) state; /* unused */
    int actual, expected;
    expected = 5;


    struct Connection *conn = malloc(sizeof(struct Connection));

    if (!conn) {
	printf("Memory error.\n");
	exit(1);
    }

    conn->rules = malloc(sizeof(struct Rules));

    if (!conn->rules) {
	printf("Memory error.\n");
	exit(1);
    }

    int i = 0;
    for (i = 0; i < MAX_RULES; i++) {
	struct Rule rule;
	rule.id = i;
	if (i < expected) {
	    rule.set = 1;
	} else {
	    rule.set = 0;
	}

	conn->rules->rules[i] = rule;
    }

    actual = get_rules_num(conn);

    assert_int_equal(actual, expected);
}

int main(void) {
    const struct CMUnitTest tests[] = {
    cmocka_unit_test(set_policy_test_allow),
    cmocka_unit_test(set_policy_test_deny),
    cmocka_unit_test(set_policy_test_reject),
    cmocka_unit_test(set_policy_test_allow_ips),
    cmocka_unit_test(set_policy_test_invalid),
    cmocka_unit_test(get_rules_num_test)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
