# COMPILER SETTINGS(FLAGS)
CCFLAG := $(CROSS_COMPILE)gcc

# DEFAULT TARGET
TARGET := writer
all: $(TARGET)

# BUILDING THE WRITER FILE
$(TARGET): writer.c
	$(CCFLAG) $< -o $@ 
	chmod +x $@
#	mv $@.o $@
	
#Execute Permissions to target file

# CLEAN TARGET
clean:
	-rm $(TARGET)

.PHONY: all clean
