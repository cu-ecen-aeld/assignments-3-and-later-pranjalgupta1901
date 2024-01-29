#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

int main(int argc, char *argv[]){

	// checking for two argumnets 
	if(argc != 3){

		openlog("FileDescriptor", LOG_CONS | LOG_PID , LOG_USER);
		syslog(LOG_PERROR, "Insufficent arguments, There should be only 2 arguments other than the program");
		closelog();
		
		return 1;
	}
	const char *filename = argv[1];
	const char *string = argv[2];

	if(string == NULL){

		openlog("FileDescriptor", LOG_CONS | LOG_PID , LOG_USER);
		syslog(LOG_PERROR, "string not found");
		closelog();
		return 1;
	}

	int fd;
	fd = open (filename, O_RDWR|O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
	if(fd == -1){
		// PRINT A ERROR MESSAG
		
		openlog("FileDescriptor", LOG_CONS | LOG_PID , LOG_USER);
		syslog(LOG_PERROR, "Error in opening of the file %s and with error code %d\n", filename, errno);
		closelog();   

		return 1;
	}
	else
	{ 

		ssize_t result = write(fd, string, strlen(string));
		if(result == -1){

			openlog("FileDescriptor", LOG_CONS | LOG_PID , LOG_USER);
			syslog(LOG_PERROR, "Unable to write to the file %s with error code %d\n", filename, errno);
			closelog();

			return 1;

		}

		close(fd);
	}	
		openlog("FileDescriptor", LOG_CONS | LOG_PID , LOG_USER);
		syslog(LOG_DEBUG, "Completed writing the file %s", filename);
		closelog();


		return 0;
}



