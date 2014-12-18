
# Set NFAST_PATH to installation directory of the headers and libraries
NFAST_PATH=	/opt/nfast

# Developer tools installation
NFAST_DEV_PATH= $(NFAST_PATH)/c/ctd/gcc
NFAST_EXAMPLES_PATH= $(NFAST_PATH)/c/ctd/examples

# We now have a single library directory, not one per component, in an
# installation, but may be using different paths per component in
# testing.
LIBPATH_SWORLD= $(NFAST_DEV_PATH)/lib
LIBPATH_HILIBS= $(NFAST_DEV_PATH)/lib
LIBPATH_NFLOG= $(NFAST_DEV_PATH)/lib
LIBPATH_CUTILS= $(NFAST_DEV_PATH)/lib

INC_SWORLD= $(NFAST_DEV_PATH)/include/sworld
INC_HILIBS= $(NFAST_DEV_PATH)/include/hilibs
INC_NFLOG= $(NFAST_DEV_PATH)/include/nflog
INC_CUTILS= $(NFAST_DEV_PATH)/include/cutils

EXAMPLES_SWORLD= $(NFAST_EXAMPLES_PATH)/sworld
EXAMPLES_HILIBS= $(NFAST_EXAMPLES_PATH)/hilibs
EXAMPLES_NFLOG= $(NFAST_EXAMPLES_PATH)/nflog
EXAMPLES_CUTILS= $(NFAST_EXAMPLES_PATH)/cutils

SRCPATH=	.

CC=		 gcc
CPPFLAGS=	   -I$(SRCPATH) \
		-I$(INC_SWORLD) \
		-I$(INC_HILIBS) \
		-I$(INC_NFLOG) \
		-I$(INC_CUTILS) \
		-I$(EXAMPLES_SWORLD) \
		-I$(EXAMPLES_HILIBS) \
		-I$(EXAMPLES_NFLOG) \
		-I$(EXAMPLES_CUTILS) \
		$(XCPPFLAGS)
CFLAGS=		-g -O0  -Wall -Wwrite-strings -Wstrict-prototypes -Wmissing-prototypes -Wno-format-zero-length -D_GNU_SOURCE -Wno-nonnull -Werror -fPIC -Wno-nonnull  $(XCFLAGS)

LINK=		  gcc
LDFLAGS= 	   $(XLDFLAGS)
LDFLAGS_THREADED= $(LDFLAGS)  $(XLDFLAGS_THREADED)
LDLIBS=		$(XLDLIBS)  -lnsl
LDLIBS_THREADED= $(XLDLIBS_THREADED) -lpthread -lrt $(LDLIBS)

# Targets ------------------------

all: key-reference

XLDLIBS= $(LIBPATH_SWORLD)/libnfkm.a \
	$(LIBPATH_HILIBS)/libnfstub.a \
	$(LIBPATH_NFLOG)/libnflog.a \
	$(LIBPATH_CUTILS)/libcutils.a \
	-lcrypto

COMMON_OBJECTS= osslbignum.o nfutil.o

COMMON_HEADERS= $(SRCPATH)/osslbignum.h $(SRCPATH)/nfutil.h

key-reference.o: key-reference.c $(COMMON_HEADERS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o key-reference.o -c $(SRCPATH)/key-reference.c

KEY-REFERENCE_OBJS= key-reference.o

key-reference: key-reference.o $(COMMON_OBJECTS)
	       $(LINK) $(LDFLAGS) -o key-reference $(KEY-REFERENCE_OBJS) $(COMMON_OBJECTS) $(LDLIBS)

testosslbignum.o: testosslbignum.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o testosslbignum.o -c $(SRCPATH)/testosslbignum.c

testosslbignum: testosslbignum.o osslbignum.o nfutil.o
	$(LINK) $(LDFLAGS) -o testosslbignum testosslbignum.o osslbignum.o nfutil.o $(LDLIBS) -lssl -lcrypto

runtest:
	gdb -ex 'break osslbignum.c:11' -ex 'break osslbignum.c:46' -ex 'break osslbignum.c:57' -ex 'break osslbignum.c:91' -ex 'break osslbignum.c:102' -ex 'break testosslbignum.c:44' testosslbignum

# Secondary targets ------------------------

clean:
	rm -f  *.o
	rm -f key-reference
