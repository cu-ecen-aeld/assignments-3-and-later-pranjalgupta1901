# COMPILER SETTINGS(FLAGS)
CC = gcc
CCFLAG := $(CROSS_COMPILE)

# DEFAULT TARGET
TARGET := writer
all: $(TARGET)

# BUILDING THE WRITER FILE
$(TARGET): writer.c
	$(CCFLAG)$(CC) $< -o $@ 
	chmod +x $@
#	mv $@.o $@
	
#Execute Permissions to target file

# CLEAN TARGET
clean:
	-rm $(TARGET)

.PHONY: all clean
