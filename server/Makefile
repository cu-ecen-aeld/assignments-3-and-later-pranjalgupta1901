# DEFAULT TARGET
CROSS_COMPILE?=

TARGET := aesdsocket
all: $(TARGET)

# BUILDING THE WRITER FILE
$(TARGET): aesdsocket.c
	${CROSS_COMPILE}$(CC) $< -o $@ 
	chmod +x $@
#	mv $@.o $@
	
#Execute Permissions to target file

# CLEAN TARGET
clean:
	-rm $(TARGET)

.PHONY: clean
