# Makefile

CC = gcc
CFLAGS = -g -Wall -Werror -O2
LFLAGS = -g
LIBS += -lpcap
OSDEF = -DLINUX

PROG = trace
SRCS = src/trace.c \
       src/checksum.c
HDRS = src/trace.h \
       src/checksum.h

all: $(PROG)

$(PROG): $(SRCS) $(HRDS)
	$(CC) $(CFLAGS) $(OSDEF) -o $(PROG) $(SRCS) $(LIBS)

clean:
	rm -f $(PROG) src/*.o
