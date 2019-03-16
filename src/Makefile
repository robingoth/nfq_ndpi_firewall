SYSARCH := $(shell arch)

CC=gcc
LINC = ../include
LIBNDPI = ../lib/nDPI/src/lib/libndpi.a
CFLAGS = -Wall -g -I../lib/nDPI/src/include -I$(LINC)
LFLAGS = -lndpi -lnetfilter_queue -lpthread -lnetfilter_conntrack -lnfnetlink -ljson

PNAME = nfdpi
OBJ = ./obj

TDIR = ./tests
TNAME = nfdpi_tests
TWRAPS = -Wl,--wrap=set_ndpi_malloc,--wrap=set_ndpi_free,--wrap=set_ndpi_flow_malloc,--wrap=set_ndpi_flow_free,--wrap=ndpi_init_detection_module,--wrap=NDPI_BITMASK_SET_ALL,--wrap=ndpi_set_protocol_detection_bitmask2,--wrap=ndpi_detection_process_packet,--wrap=get_flow_info
TLFLAGS = -lcmocka


#########################################################################
all: $(PNAME)
#all: $(PNAME) $(TDIR)/$(TNAME)

########################### OBJECT -> BINARY ###########################
nfdpi: $(OBJ)/nfdpi.o $(OBJ)/ndpi_helper.o $(OBJ)/conntrack_helper.o $(LIBNDPI)
	$(CC) -o $@ $(OBJ)/nfdpi.o $(OBJ)/ndpi_helper.o $(OBJ)/conntrack_helper.o $(LIBNDPI) $(LFLAGS)

$(TDIR)/nfdpi_tests: $(TDIR)/nfdpi_helper_tests.c $(OBJ)/nfdpi_helper_tests.o $(OBJ)/ndpi_helper.o $(LIBNDPI)
	$(CC) -o $(TDIR)/$@ $(TLFLAGS) $(TWRAPS) $(LIBNDPI)
############################ SOURCE -> OBJECT###########################
$(OBJ)/nfdpi.o: nfdpi.c
	$(CC) -o $@ -c $(CFLAGS) nfdpi.c

$(OBJ)/ndpi_helper.o: ndpi_helper.c $(LINC)/ndpi_helper.h $(LINC)/conntrack_helper.h
	$(CC) -o $@ -c $(CFLAGS) ndpi_helper.c

$(OBJ)/conntrack_helper.o: conntrack_helper.c $(LINC)/conntrack_helper.h
	$(CC) -o $@ -c $(CFLAGS) conntrack_helper.c

$(OBJ)/nfdpi_helper_tests.o: $(TDIR)/nfdpi_helper_tests.c
	$(CC) -o $@ -c $(CFLAGS) $(TDIR)/nfdpi_helper_tests.c
#########################################################################
test: $(TNAME)
	./tests/$(TNAME)

#########################################################################
clean:
	rm -f $(OBJ)/*.o *.o $(PNAME) $(TDIR)/$(TNAME)

#########################################################################
