# DEFAULT TARGET
TARGET := aesdsocket
all: $(TARGET)

# BUILDING THE WRITER FILE
$(TARGET): aesdsocket.c
	$(CC) $< -o $@ -lrt -lpthread
	chmod +x $@
#	mv $@.o $@
	
#Execute Permissions to target file

# CLEAN TARGET
clean:
	-rm $(TARGET)

.PHONY: clean
