SHELL=/bin/bash
CC=gcc
CFLAGS=-g -Wall -std=c99 -I.
LFLAGS=-lcrypto
DEPS=util.h
OBJ=rsacrypt.o util.o

all:rsacrypt

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

rsacrypt:$(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LFLAGS)

delete:
	rm rsacrypt

clean:
	rm -f *.o
