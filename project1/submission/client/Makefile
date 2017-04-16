CC=gcc
CFLAGS=-Wall -I.
LDFLAGS=-lpthread

UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
	CFLAGS += -DNORT
else
	LDFLAGS += -lrt
endif

EXE = client

OBJ = client.o mtcp_client.o

${EXE}: ${OBJ}
	${CC} ${CFLAGS} -o ${EXE} ${OBJ} ${LDFLAGS}

clean:
	rm -f ${EXE} ${OBJ}
