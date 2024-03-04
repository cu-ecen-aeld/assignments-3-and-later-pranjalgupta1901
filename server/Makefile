CC ?= $(CROSS_COMPIPLE)gcc
CFLAGS ?= -g -Wall -Werror
LDFLAGS ?= -lpthread -lrt
TARGET ?= aesdsocket
all: aesdsocket

# BUILDING THE WRITER FILE
aesdsocket: aesdsocket.c
	$(CC) $(CFLAGS) $^ -o $@ $(INCLUDES) $(LDFLAGS)

# CLEAN TARGET
clean:
	-rm aesdsocket

.PHONY: clean
