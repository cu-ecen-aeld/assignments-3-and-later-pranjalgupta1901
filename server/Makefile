# DEFAULT TARGET

CC ?= $(CROSS_COMPIPLE)gcc
CFLAGS ?= -g -Wall -Werror
LDFLAGS ?= -lpthread -lrt
TARGET := aesdsocket
all: $(TARGET)

# BUILDING THE WRITER FILE
$(TARGET): aesdsocket.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
	chmod +x $@
#	mv $@.o $@
	
#Execute Permissions to target file

# CLEAN TARGET
clean:
	-rm $(TARGET)

.PHONY: clean
