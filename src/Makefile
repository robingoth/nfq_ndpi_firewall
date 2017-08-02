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
NH_TESTS = NdpiHelperTests

CC=gcc
CFLAGS= -Wall -g -I$(INCDIR) -I$(NDPIDIR)/src/include $(LIBSDIR)/nDPI/lib/libndpi.a
CFLAGS2 = -Wall -g -I$(INCDIR) -L/usr/local/lib 

TESTS_CFLAGS = -g -Wall -I$(INCDIR) -I$(NDPIDIR)/src/include -L/usr/local/lib $(LIBSDIR)/nDPI/lib/libndpi.a
NH_WRAPS = -Wl,--wrap=set_ndpi_malloc,--wrap=set_ndpi_free,--wrap=set_ndpi_flow_malloc,--wrap=set_ndpi_flow_free,--wrap=ndpi_init_detection_module,--wrap=NDPI_BITMASK_SET_ALL,--wrap=ndpi_set_protocol_detection_bitmask2,--wrap=ndpi_detection_process_packet,--wrap=get_flow_info

LIBS = -lndpi -lnetfilter_queue -lpthread -lnetfilter_conntrack
TESTLIBS = -lcmocka

_DEPS = ndpi_helper.h conntrack_helper.h
# Replace all filenames in dependencies with a relative path
DEPS = $(patsubst %, $(INCDIR)/%, $(_DEPS))

_OBJS = nfqueue_test.o ndpi_helper.o conntrack_helper.o
_OBJS_NH_TESTS = ndpi_helper_tests.o ndpi_helper.o

# Replace all filenames in objects with a relative path
OBJS = $(patsubst %, $(OBJDIR)/%, $(_OBJS))
OBJS_NH_TESTS = $(patsubst %, $(OBJDIR)/%, $(_OBJS_NH_TESTS))

$(OBJDIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) 

$(OBJDIR)/%.o: $(TESTSDIR)/%.c $(DEPS)
	$(CC) -c -o $@ $< $(TESTS_CFLAGS)  

all: $(PROGRAMNAME) 

$(PROGRAMNAME): $(OBJS) 
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

$(NH_TESTS): $(OBJS_NH_TESTS)
	$(CC) -o $(TESTSDIR)/$@ $^ $(TESTS_CFLAGS) $(NH_WRAPS) $(TESTLIBS) 

test: $(NH_TESTS)
	$(TESTSDIR)/$(NH_TESTS)

clean:
	rm -f $(OBJDIR)/*.o $(PROGRAMNAME) $(TESTSDIR)/$(NH_TESTS)
