# **********************************************************
# *       This file has to stay inside the src folder      *
# **********************************************************

# directories with files
INCDIR = ../include
OBJDIR = obj
LIBSDIR = ../lib
NDPIDIR = $(LIBSDIR)/nDPI
TESTSDIR = ./tests

PROGRAMNAME = NdpiNfqueueFirewall
PROGRAMNAME2 = RuleManager

RM_TESTS = RuleHelperTests
NH_TESTS = NdpiHelperTests

CC=gcc
CFLAGS= -Wall -g -I$(INCDIR) -I$(NDPIDIR)/src/include $(LIBSDIR)/nDPI/lib/libndpi.a
CFLAGS2 = -Wall -g -I$(INCDIR) -L/usr/local/lib 

TESTS_CFLAGS = -g -Wall -I$(INCDIR) -I$(NDPIDIR)/src/include $(LIBSDIR)/nDPI/lib/libndpi.a
RM_WRAPS = -Wl,--wrap=fopen,--wrap=fread
NH_WRAPS = -Wl,--wrap=set_ndpi_malloc,--wrap=set_ndpi_free,--wrap=set_ndpi_flow_malloc,--wrap=set_ndpi_flow_free,--wrap=ndpi_init_detection_module,--wrap=NDPI_BITMASK_SET_ALL,--wrap=ndpi_set_protocol_detection_bitmask2,--wrap=ndpi_detection_process_packet

LIBS = -lndpi -lnetfilter_queue -lpcre
TESTLIBS = -lcmocka -lpcre

_DEPS = ndpi_helper.h rule_helper.h
# Replace all filenames in dependencies with a relative path
DEPS = $(patsubst %, $(INCDIR)/%, $(_DEPS))

_OBJS = nfqueue_test.o ndpi_helper.o rule_helper.o
_OBJS2 = rule_manager.o rule_helper.o
_OBJS_RH_TESTS = rule_helper_tests.o rule_helper.o
_OBJS_NH_TESTS = ndpi_helper_tests.o ndpi_helper.o

# Replace all filenames in objects with a relative path
OBJS = $(patsubst %, $(OBJDIR)/%, $(_OBJS))
OBJS2 = $(patsubst %, $(OBJDIR)/%, $(_OBJS2))
OBJS_RH_TESTS = $(patsubst %, $(OBJDIR)/%, $(_OBJS_RH_TESTS))
OBJS_NH_TESTS = $(patsubst %, $(OBJDIR)/%, $(_OBJS_NH_TESTS))

$(OBJDIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) 

$(OBJDIR)/%.o: $(TESTSDIR)/%.c $(DEPS)
	$(CC) -c -o $@ $< $(TESTS_CFLAGS)  

all: $(PROGRAMNAME) $(PROGRAMNAME2) 

$(PROGRAMNAME): $(OBJS) 
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

$(PROGRAMNAME2): $(OBJS2) 
	$(CC) -o $@ $^ $(CFLAGS2) $(LIBS) 

$(RM_TESTS): $(OBJS_RH_TESTS)
	$(CC) -o $(TESTSDIR)/$@ $^ $(TESTS_CFLAGS) $(RM_WRAPS) $(TESTLIBS)

$(NH_TESTS): $(OBJS_NH_TESTS)
	$(CC) -o $(TESTSDIR)/$@ $^ $(TESTS_CFLAGS) $(NH_WRAPS) $(TESTLIBS) 

test: $(RM_TESTS) $(NH_TESTS)
	$(TESTSDIR)/$(RM_TESTS) && $(TESTSDIR)/$(NH_TESTS)

clean:
	rm -f $(OBJDIR)/*.o $(PROGRAMNAME) $(PROGRAMNAME2) $(TESTSDIR)/$(RM_TESTS) $(TESTSDIR)/$(NH_TESTS)
