#This makefile is used to generate coap server and client

ODIR = ./out

#Set all your common object files

_BRSKI_OBJ = brski.o client_request.o JP_stateless.o json.o
BRSKI_OBJ = $(patsubst %,$(ODIR)/%,$(_BRSKI_OBJ))

_OSC_OBJ = oscore.o oscore-context.o oscore_oauth.o\
 oscore_mbedtls.o   cose.o cbor.o bn.o
#oscore-crypto.o dtls-hmac.o 

OSC_OBJ = $(patsubst %,$(ODIR)/%,$(_OSC_OBJ))

_AUTH_OBJ = oscore_oauth.o oscore-group.o
AUTH_OBJ = $(patsubst %,$(ODIR)/%,$(_AUTH_OBJ))

_edDSA_OBJ = edDSA_keypair.o edDSA_sc.o ecc.o edDSA_seed.o edDSA_sign.o edDSA_verify.o \
edDSA_add_scalar.o edDSA_fe.o edDSA_ge.o	edDSA_key_exchange.o  edDSA_keypair.o sha512.o

_OBJ = $(_edDSA_OBJ) address.o coap-keystore-simple.o	 \
aes-128.o		coap_notls.o    brski_util.o	\
async.o		coap_mbedtls.o  pdu.o \
block.o		coap_session.o  resource.o \
cbor.o		coap_time.o     coap_tinydtls.o	   encode.o \
coap_debug.o     str.o           cbor_decode.o \
coap_event.o     mem.o           subscribe.o \
coap_gnutls.o	net.o uri.o     coap_io.o \
coap_hashkey.o	option.o        coap_tcp.o		  	

OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

#Set the server files
_BOX_SERVER_OBJ = GM_server.o switch_server.o client_request.o \
AS_server.o main_box.o

BOX_SERVER_OBJ = $(patsubst %,$(ODIR)/%,$(_BOX_SERVER_OBJ))

#Set any dependant header files so that if they are edited they cause a complete re-compile (e.g. main.h some_subfunctions.h some_definitions_file.h ), or leave blank
DEPS = ./include/*.h

#Any special libraries you are using in your project (e.g. -lbcm2835 -lrt `pkg-config --libs gtk+-3.0` ), or leave blank
LIBS = -lssl -lcrypto -L/usr/local/ssl/lib -lmbedtls -lmbedx509 -lmbedcrypto

#LIBS = -lmbedtls -lmbedx509 -lmbedcrypto

#Set any compiler flags you want to use
CFLAGS = -I./include -O2 -D_GNU_SOURCE 

WFLAGS = -Wall -Wcast-qual -Wswitch-default -Wswitch-enum -Wunused -Wwrite-strings -Wlogical-op -Wunused-result 

DFLAGS = -DHAVE_CONFIG_H -DCOAP_DISABLE_TCP -DWITH_OSCORE -DWITH_JOIN_PROXY

#Set the compiler you are using ( gcc for C or g++ for C++ )
CC = gcc -std=c99

#Set the filename extensiton of your C files (e.g. .o or .cpp )
EXTENSION = .c

#define a rule that applies to all files ending in the .o suffix, which says that the .o file depends upon the .c version of the file and all the .h files included in the DEPS macro.  Compile each object file
$(ODIR)/%.o: ./src/%$(EXTENSION) $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) $(WFLAGS) $(DFLAGS)

#define the applications that need to be generated 

apps = coap_client coap_server GM_client group_client box_server pledge masa registrar test
 
all: $(apps)

#Combine them into the output file
#Set your desired exe output file name here

GM_client: $(OBJ) $(OSC_OBJ) $(AUTH_OBJ) ./out/GM_client.o ./out/JP_dummy.o
	$(CC) -o $@ $^ $(CFLAGS) $(WFLAGS) $(DFLAGS) $(LIBS)

controller: $(OBJ) $(OSC_OBJ) ./out/controller.o ./out/JP_dummy.o
	$(CC) -o $@ $^ $(CFLAGS) $(WFLAGS) $(DFLAGS) $(LIBS)

coap_client: $(OBJ) $(OSC_OBJ) ./out/coap_client.o ./out/edhoc.o ./out/JP_dummy.o
	$(CC) -o $@ $^ $(CFLAGS) $(WFLAGS) $(DFLAGS) $(LIBS)

group_client: $(OBJ) $(OSC_OBJ) $(AUTH_OBJ) ./out/group_client.o ./out/JP_dummy.o
	$(CC) -o $@ $^ $(CFLAGS) $(WFLAGS) $(DFLAGS) $(LIBS)

box_server: $(OBJ) $(BOX_SERVER_OBJ) $(OSC_OBJ) $(AUTH_OBJ) ./out/JP_dummy.o ./out/edhoc.o
	$(CC) -o $@ $^ $(CFLAGS) $(WFLAGS) $(DFLAGS) $(LIBS)

coap_server: $(OBJ) $(OSC_OBJ) ./out/coap_server.o ./out/edhoc.o ./out/JP_dummy.o
	$(CC) -o $@ $^ $(CFLAGS) $(WFLAGS) $(DFLAGS) $(LIBS)

registrar: $(OBJ) $(OSC_OBJ) $(BRSKI_OBJ) ./out/Registrar_server.o ./out/edhoc.o
	$(CC) -o $@ $^ $(CFLAGS) $(WFLAGS) $(DFLAGS) $(LIBS) -L/usr/local/ssl/lib -lcrypto -lssl
	
pledge: $(OBJ) $(OSC_OBJ) $(BRSKI_OBJ) ./out/pledge.o ./out/JP_server.o ./out/edhoc.o \
 ./out/main_pledge.o
	$(CC) -o $@ $^ $(CFLAGS) $(WFLAGS) $(DFLAGS) $(LIBS)	
	
edhoc_client: $(OBJ) $(OSC_OBJ) $(BRSKI_OBJ) ./out/edhoc_client.o ./out/edhoc.o
	$(CC) -o $@ $^ $(CFLAGS) $(WFLAGS) $(DFLAGS) $(LIBS)

masa: $(OBJ) $(OSC_OBJ) $(BRSKI_OBJ) ./out/masa_server.o
	$(CC) -o $@ $^ $(CFLAGS) $(WFLAGS) $(DFLAGS) $(LIBS)

test: $(OBJ) $(OSC_OBJ) $(BRSKI_OBJ) ./out/test.o \
 ./out/pledge.o ./out/edhoc.o ./out/JP_server.o
	$(CC) -o $@ $^ $(CFLAGS) $(WFLAGS) $(DFLAGS) $(LIBS)
	
#Cleanup
.PHONY: clean

clean:
	rm -f $(ODIR)/*.o $(apps)

