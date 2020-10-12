CC=gcc
CFLAGS=-Wall -g
LDLIBS=-lssl -lcrypto -pthread

all: checksec

checksec: checksec.o
checksec.o: checksec.c

clean:
	-rm -rf checksec.o checksec
