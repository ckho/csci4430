CC=gcc
CFLAGS=-Wall -I.
LDFLAGS=-lnfnetlink -lnetfilter_queue

UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
	CFLAGS += -DNORT
else
	LDFLAGS += -lrt
endif

EXE = nat

OBJ = nat.o table.o checksum.o

${EXE}: ${OBJ}
	${CC} ${CFLAGS} -o ${EXE} ${OBJ} ${LDFLAGS}

clean:
	rm -f ${EXE} ${OBJ}
