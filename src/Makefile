# **********************************************************
# *       This file has to stay inside the src folder      *
# **********************************************************

# directories with files
INCDIR = ../include
OBJDIR = obj
LIBSDIR = ../lib
NDPIDIR = $(LIBSDIR)/nDPI

PROGRAMNAME = ndpi_nfqueue_firewall

CC=gcc
CFLAGS= -Wall -g -I$(INCDIR) -I$(NDPIDIR)/src/include $(LIBSDIR)/nDPI/lib/libndpi.a

LIBS = -lndpi -lnetfilter_queue

_DEPS = ndpi_helper.h
# Replace all filenames in dependencies with a relative path
DEPS = $(patsubst %, $(INCDIR)/%, $(_DEPS))

_OBJS = nfqueue_test.o ndpi_helper.o
# Replace all filenames in objects with a relative path
OBJS = $(patsubst %, $(OBJDIR)/%, $(_OBJS))

$(OBJDIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(PROGRAMNAME): $(OBJS) 
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm -f $(OBJDIR)/*.o $(PROGRAMNAME)
