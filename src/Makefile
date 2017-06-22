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

RM_TESTS = RuleManagerTests

CC=gcc
CFLAGS= -Wall -g -I$(INCDIR) -I$(NDPIDIR)/src/include $(LIBSDIR)/nDPI/lib/libndpi.a
CFLAGS2 = -Wall -g -I$(INCDIR) -L/usr/local/lib 

CTESTS_FLAGS = -g -Wall -I$(INCDIR)
RM_WRAPS = -Wl,--wrap=func

LIBS = -lndpi -lnetfilter_queue
TESTLIBS = -lcmocka

_DEPS = ndpi_helper.h rule_helper.h
# Replace all filenames in dependencies with a relative path
DEPS = $(patsubst %, $(INCDIR)/%, $(_DEPS))

_OBJS = nfqueue_test.o ndpi_helper.o rule_helper.o
_OBJS2 = rule_manager.o rule_helper.o
_OBJSTEST = rule_manager_tests.o rule_helper.o

# Replace all filenames in objects with a relative path
OBJS = $(patsubst %, $(OBJDIR)/%, $(_OBJS))
OBJS2 = $(patsubst %, $(OBJDIR)/%, $(_OBJS2))
OBJSTEST = $(patsubst %, $(OBJDIR)/%, $(_OBJSTEST))


$(OBJDIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(OBJDIR)/%.o: $(TESTSDIR)/%.c $(DEPS)
	$(CC) -c -o $@ $< $(CTESTS_FLAGS) 

$(PROGRAMNAME): $(OBJS) 
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

$(PROGRAMNAME2): $(OBJS2) 
	$(CC) -o $@ $^ $(CFLAGS2) -lpcre 

$(RM_TESTS): $(OBJSTEST)
	$(CC) -o $(TESTSDIR)/$@ $^ $(CTESTS_FLAGS) $(RM_WRAPS) $(TESTLIBS)

test:
	$(TESTSDIR)/$(RM_TESTS)

clean:
	rm -f $(OBJDIR)/*.o $(PROGRAMNAME) $(PROGRAMNAME2)
