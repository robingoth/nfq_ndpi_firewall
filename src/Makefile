# **********************************************************
# *       This file has to stay inside the src folder      *
# **********************************************************

# directories with files
INCDIR = ../include
OBJDIR = obj
LIBSDIR = ../lib
NDPIDIR = $(LIBSDIR)/nDPI

PROGRAMNAME = NdpiNfqueueFirewall
PROGRAMNAME2 = RuleManager

CC=gcc
CFLAGS= -Wall -g -I$(INCDIR) -I$(NDPIDIR)/src/include $(LIBSDIR)/nDPI/lib/libndpi.a
CFLAGS2 = -Wall -g -I$(INCDIR)

LIBS = -lndpi -lnetfilter_queue

_DEPS = ndpi_helper.h rule_helper.h
_DEPS2 = rule_helper.h
# Replace all filenames in dependencies with a relative path
DEPS = $(patsubst %, $(INCDIR)/%, $(_DEPS))
DEPS2 = $(patsubst %, $(INCDIR)/%, $(_DEPS2))

_OBJS = nfqueue_test.o ndpi_helper.o rule_helper.o
_OBJS2 = rule_manager.o rule_helper.o
# Replace all filenames in objects with a relative path
OBJS = $(patsubst %, $(OBJDIR)/%, $(_OBJS))
OBJS2 = $(patsubst %, $(OBJDIR)/%, $(_OBJS2))

$(OBJDIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(PROGRAMNAME): $(OBJS) 
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

$(PROGRAMNAME2): $(OBJS2) 
	$(CC) -o $@ $^ $(CFLAGS2)

clean:
	rm -f $(OBJDIR)/*.o $(PROGRAMNAME) $(PROGRAMNAME2)
