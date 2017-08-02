#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <cmocka.h>
#include <string.h>

#include "ndpi_helper.h"
#include "ndpi_main.h"

/* Wrap functions */
void __wrap_set_ndpi_malloc()
{
    // do nothing
}

void __wrap_set_ndpi_free()
{
    // do nothing
}

void __wrap_set_ndpi_flow_malloc()
{
    // do nothing
}

void __wrap_set_ndpi_flow_free()
{
    // do nothing
}

struct ndpi_detection_module_struct *__wrap_ndpi_init_detection_module()
{
    struct ndpi_detection_module_struct *ndpi_str = malloc(sizeof(struct ndpi_detection_module_struct));
    
    if(ndpi_str == NULL) {
	return NULL;
    } else {
	memset(ndpi_str, 0, sizeof(struct ndpi_detection_module_struct));
	return ndpi_str;
    }
}

void __wrap_NDPI_BITMASK_SET_ALL(){
    // do nothing
}

void __wrap_ndpi_set_protocol_detection_bitmask2()
{
    // do nothing
}

ndpi_protocol __wrap_ndpi_detection_process_packet()
{
    int master_protocol = mock_type(int);
    int app_protocol = mock_type(int);
    ndpi_protocol res = { master_protocol, app_protocol }; 
    return res;
}

struct flow_info *__wrap_get_flow_info()
{
    struct flow_info *ret = malloc(sizeof(struct flow_info));
    if (ret == NULL) {
	printf("error during flow allocation");
    }

    return ret;
}

/********************/

/* Tests */

static void setup_detection_test_success(void **state)
{
    (void) state; /* unused */

    struct ndpi_detection_module_struct *expected = malloc(sizeof(
		struct ndpi_detection_module_struct));

    if(expected == NULL) {
	printf("Malloc failed.");
	exit(1);
    } else {
	memset(expected, 0, sizeof(struct ndpi_detection_module_struct));
    }

    struct ndpi_detection_module_struct *actual = setup_detection();

    assert_memory_equal(expected, actual, sizeof(struct ndpi_detection_module_struct));

    free(expected);
    free(actual);
}

static void detect_protocol_test_success(void **state)
{
    (void) state; /* unused */

    ndpi_protocol expected = { 23, 100 };
    
    will_return(__wrap_ndpi_detection_process_packet, 23);
    will_return(__wrap_ndpi_detection_process_packet, 100);

    const unsigned char *packet; 
    const unsigned short packetlen = 10;
    struct timeval timestamp = { 100, 1000 };

    struct ndpi_detection_module_struct *ndpi_struct = malloc(sizeof(
		struct ndpi_detection_module_struct));

    if(ndpi_struct == NULL) {
	printf("Malloc failed.");
	exit(1);
    } else {
	memset(ndpi_struct, 0, sizeof(struct ndpi_detection_module_struct));
    }

    struct ndpi_workflow *workflow = ndpi_calloc(1, sizeof(struct ndpi_workflow));
    if (workflow == NULL) {
	printf("ERROR: workflow initialization failed");
	exit(1);
    }

    workflow->num_roots = 512;
    workflow->max_flows = 20000000;
    workflow->max_idle_time = 600;

    workflow->flow_count = 0;

    workflow->ndpi_flows_root = ndpi_calloc(workflow->num_roots, sizeof(void *));
    if (workflow->ndpi_flows_root == NULL) {
	printf("ERROR: ndpi_flows_root initialization failed");
	exit(1);
    }

    workflow->idle_flows = ndpi_calloc(10, sizeof(struct flow_info *));
    if (workflow->idle_flows == NULL) {
	printf("ERROR: idle_flows initialization failed");
	exit(1);
    }

    workflow->ndpi_struct = ndpi_struct;	

    ndpi_protocol actual = detect_protocol(packet, packetlen, timestamp, workflow);

    assert_int_equal(expected.master_protocol, actual.master_protocol);
    assert_int_equal(expected.app_protocol, actual.app_protocol);

    free(ndpi_struct);
    free(workflow->idle_flows);
    free(workflow->ndpi_flows_root);
    free(workflow);
}

int main(void) {
    const struct CMUnitTest tests[] = {
	cmocka_unit_test(setup_detection_test_success),
	cmocka_unit_test(detect_protocol_test_success)
    };
    
    return cmocka_run_group_tests(tests, NULL, NULL);
}
