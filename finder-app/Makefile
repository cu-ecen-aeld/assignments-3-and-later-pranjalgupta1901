# DEFAULT TARGET
TARGET := writer
all: $(TARGET)

# BUILDING THE WRITER FILE
$(TARGET): writer.c
	$(CC) $< -o $@ 
	chmod +x $@
#	mv $@.o $@
	
#Execute Permissions to target file

# CLEAN TARGET
clean:
	-rm $(TARGET)

.PHONY: clean
