#Makefile for comipling server.c and client.c files
#@chinmay.shah@colorado.edu
#reference: 1)http://mrbook.org/blog/tutorials/make/
#			2)http://mercury.pr.erau.edu/~siewerts/cec450/code/example-sync/

# the compiler to be used	
CC=gcc 
CDEFS = 
#flags used during compilation
CFLAGS= -o
LDFLAGS= -lcrypto -lssl -lpthread

PRODUCT= webproxy 

all: $(PRODUCT)
	
webproxy: server.c
		$(CC) $(CFLAGS) $@ $^ $(LDFLAGS)

clean:
	-rm -f *.o *.NEW *~ *.d
	-rm -f ${PRODUCT} ${GARBAGE}
 
