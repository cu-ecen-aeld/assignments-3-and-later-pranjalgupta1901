#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <errno.h>
#include <netdb.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include "queue.h"
#include "../aesd-char-driver/aesd_ioctl.h"
#define FILE_SIZE 1024
#define MAX_CONNECTIONS 100

int socket_fd, client_fd;
pthread_mutex_t aesdsocket_mutex;
pthread_t aesdsocket_threads[MAX_CONNECTIONS];
int thread_count = 0;
volatile bool signal_detected = false;
struct sockaddr_in client_addr;
char ip_addr[INET6_ADDRSTRLEN];
time_t t;
struct tm *tmp;
char MY_TIME[50];
int fd;
int flag = 0;
#define USE_AESD_CHAR_DEVICE 1

struct thread_data_t
{
	int client_fd;
	pthread_t thread_id;
	bool is_socket_complete;
	SLIST_ENTRY(thread_data_t)
	entries;
};

void daemonize(void);
#if USE_AESD_CHAR_DEVICE
char filename[] = "/dev/aesdchar";
const char *aesd_ioctl_cmd = "AESDCHAR_IOCSEEKTO:";
#else
char filename[] = "/var/tmp/aesdsocketdata";
#endif

void mysig(int signo)
{
	if (signo == SIGINT || signo == SIGTERM)
	{
		signal_detected = true;
	}
}


void *handle_client(void *arg)
{struct thread_data_t *data = (struct thread_data_t *)arg;
syslog(LOG_DEBUG, "Receive Started\n");
bool rec_complete = false;
int offset = 0;
char *data_ptr = (char *)malloc(sizeof(char) * FILE_SIZE);
#if USE_AESD_CHAR_DEVICE
int cmd_length = strlen(aesd_ioctl_cmd);
#endif


int fd;
 fd = open(filename, O_CREAT | O_APPEND | O_RDWR, S_IRWXU | S_IRGRP | S_IROTH);
if (fd == -1)
{
    syslog(LOG_PERROR, "Error opening or creating the file %s with error code %d\n", filename, errno);
    close(data->client_fd);
    data->is_socket_complete = true;
    free(data_ptr);
    return NULL;
}
syslog(LOG_DEBUG, "File opened successfully\n");

while (!rec_complete)
{
    ssize_t bytes_rec = recv(data->client_fd, data_ptr + offset, sizeof(char) * (FILE_SIZE - offset), 0);
    if (bytes_rec <= 0)
    {
        break;
    }
    
#if (USE_AESD_CHAR_DEVICE == 1)
    // Check if the received data matches the AESD IOCTL command
    if (strncmp(data_ptr, aesd_ioctl_cmd, cmd_length) == 0)
    {
        struct aesd_seekto aesd_seekto_data;

        // Parse the received command to extract seek parameters
        int command_count = sscanf(data_ptr, "AESDCHAR_IOCSEEKTO:%d,%d", &aesd_seekto_data.write_cmd,
                                    &aesd_seekto_data.write_cmd_offset);

        if (command_count != 2)
        {
            syslog(LOG_ERR, "Failed to parse IOCTL command: %s", strerror(errno));
        }
        else
        {
            // Executing the IOCTL command to seek to the specified position
            if (ioctl(fd, AESDCHAR_IOCSEEKTO, &aesd_seekto_data) != 0)
            {
         
                syslog(LOG_ERR, "Failed to execute IOCTL command: %s", strerror(errno));
            }
        }

        // After handling the IOCTL command, proceeding to read data
        goto read;
    }

#endif



    offset += bytes_rec;
    syslog(LOG_DEBUG, "Received %zd bytes of data\n", bytes_rec);

    if (offset >= FILE_SIZE)
    {
        char *new_data_ptr = (char *)realloc(data_ptr, sizeof(char) * (offset + FILE_SIZE));
        if (new_data_ptr != NULL)
        { // realloc success
            data_ptr = new_data_ptr;
        }
        else
        { // realloc failed
            syslog(LOG_PERROR, "realloc failed with error code %d\n", errno);
            close(data->client_fd);
            data->is_socket_complete = true;
            free(data_ptr);
            close(fd);
            return NULL;
        }
    }
    
    if (memchr(data_ptr, '\n', offset) != NULL)
    {
        rec_complete = true;
        syslog(LOG_DEBUG, "Received complete message\n");
    }
}

// Lock the mutex before writing to the file if receive is complete
if (rec_complete)
{
    if (pthread_mutex_lock(&aesdsocket_mutex) != 0)
    {
        syslog(LOG_PERROR, "Mutex Lock Failed with error code %d\n", errno);
        close(data->client_fd);
        data->is_socket_complete = true;
        close(fd);
        free(data_ptr);
        return NULL;
    }

    ssize_t result = write(fd, data_ptr, offset);
    if (result == -1)
    {
        syslog(LOG_PERROR, "Unable to write to the file %s with error code %d\n", filename, errno);
        close(fd);
        free(data_ptr);
        close(data->client_fd);
        data->is_socket_complete = true;
        pthread_mutex_unlock(&aesdsocket_mutex);
        return NULL;
    }

    pthread_mutex_unlock(&aesdsocket_mutex);
    syslog(LOG_DEBUG, "Data written to file successfully\n");
}

#if (USE_AESD_CHAR_DEVICE == 0)
	    close(fd);
            fd = open(filename, O_CREAT | O_RDONLY, S_IRWXU | S_IRGRP | S_IROTH);
            if (fd == -1)
            {
                syslog(LOG_PERROR, "Error opening or creating the file %s with error code %d\n", filename, errno);
   	 	close(data->client_fd);
    		data->is_socket_complete = true;
    		free(data_ptr);
    		return NULL;
    	    }
#endif

	syslog(LOG_DEBUG, "Sending Started\n");
  
	int bytes_send;
	bool send_complete = false;

	char data_buf[FILE_SIZE];
	
read:

	while (!send_complete)
	{
    bytes_send = read(fd, data_buf, FILE_SIZE);
    if (bytes_send < 0)
    {
        syslog(LOG_PERROR, "Error reading data from the file for sending\n");
        close(data->client_fd);
        data->is_socket_complete = true;
        close(fd);
        free(data_ptr);
        break;
    }
    else if (bytes_send == 0)
    {
        send_complete = true;
        break;
    }

    int sent_actual = send(data->client_fd, data_buf, bytes_send, 0);
    if (sent_actual != bytes_send)
    {
        syslog(LOG_PERROR, "Error sending data to socket\n");
        close(data->client_fd);
        data->is_socket_complete = true;
        close(fd);
        free(data_ptr);
        break;
    }
    syslog(LOG_DEBUG, "Sent %d bytes of data\n", sent_actual);
}

close(fd);
close(data->client_fd);
free(data_ptr);
syslog(LOG_DEBUG, "File closed and memory freed\n");

return NULL;


}

void setup_signal()
{
	struct sigaction sa;

	sa.sa_handler = &mysig;
	sigemptyset(&(sa.sa_mask));
	sa.sa_flags = 0;

	if (sigaction(SIGINT, &sa, NULL) == -1)
	{
		syslog(LOG_PERROR, "Unable to initialise SIGINT signal handler with error code %d\n", errno);
		exit(EXIT_FAILURE);
	}

	if (sigaction(SIGTERM, &sa, NULL) == -1)
	{
		syslog(LOG_PERROR, "Unable to initialise SIGTERM signal handler with error code %d\n", errno);
		exit(EXIT_FAILURE);
	}
}

void timer_handler(int signum)
{
	time(&t);
	tmp = localtime(&t);

	// using strftime to convert time structure to string
	strftime(MY_TIME, sizeof(MY_TIME), "timestamp: %Y %m %d %H:%M:%S\n", tmp);

	int fd = open(filename,  O_WRONLY | O_APPEND, 0664);

	if (fd == -1)
	{
		syslog(LOG_PERROR, "Error in opening or creating the file %s with error code %d\n", filename, errno);
		return;
	}

	// Convert time string to bytes for writing to file
	size_t time_length = strlen(MY_TIME);

	// Locking mutex to ensure thread safety
	if (pthread_mutex_lock(&aesdsocket_mutex) != 0)
	{
		syslog(LOG_PERROR, "Mutex Lock Failed with error code %d\n", errno);
		close(fd);
		return;
	}

	ssize_t result = write(fd, MY_TIME, time_length);

	if (result == -1)
	{
		syslog(LOG_PERROR, "Unable to write to the file %s with error code %d\n", filename, errno);
	}

	pthread_mutex_unlock(&aesdsocket_mutex);
	close(fd);
}
int main(int argc, char *argv[])
{
	struct addrinfo hints, *result;
	int errorcode;
	const char *port = "9000";

	openlog(NULL, LOG_CONS | LOG_PID, LOG_USER);

#if !(USE_AESD_CHAR_DEVICE)	// Initialize mutex
	if (pthread_mutex_init(&aesdsocket_mutex, NULL) != 0)
	{
		syslog(LOG_PERROR, "Mutex initialization failed\n");
		closelog();
		exit(EXIT_FAILURE);
	}
#endif
	// Setup signal handlers
	setup_signal();

	// Initialize the list for thread data
	SLIST_HEAD(thread_data_head, thread_data_t)
	thread_data_head;
	SLIST_INIT(&thread_data_head);

	// Set up address information
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	errorcode = getaddrinfo(NULL, port, &hints, &result);
	if (errorcode != 0)
	{
		syslog(LOG_PERROR, "Error in getting address using getaddrinfo with error code %d\n", errno);
		closelog();
		exit(EXIT_FAILURE);
	}

	// Create a socket
	socket_fd = socket(result->ai_family, result->ai_socktype, 0);
	if (socket_fd == -1)
	{
		syslog(LOG_PERROR, "Socket creation failed with error code %d\n", errno);
		closelog();
		exit(EXIT_FAILURE);
	}
	syslog(LOG_DEBUG, "Socket Created with Socket Id %d\n", socket_fd);

	// Set socket option
	int var_setsockopt = 1;
	if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &var_setsockopt, sizeof(int)) == -1)
	{
		syslog(LOG_PERROR, "Socket reuse address failed with error code %d\n", errno);
		closelog();
		exit(EXIT_FAILURE);
	}

	// Bind the socket
	errorcode = bind(socket_fd, result->ai_addr, result->ai_addrlen);
	if (errorcode == -1)
	{
		close(socket_fd);
		syslog(LOG_PERROR, "Socket bind failed with error code %d\n", errno);
		closelog();
		exit(EXIT_FAILURE);
	}
	syslog(LOG_DEBUG, "Bind Successful\n");

	freeaddrinfo(result);

	if (argc > 1 && strcmp(argv[1], "-d") == 0)
	{
		syslog(LOG_USER, "Daemonizing process\n");
		daemonize();
	}

	// Listen for connections
	errorcode = listen(socket_fd, 50);
	if (errorcode == -1)
	{
		close(socket_fd);
		syslog(LOG_PERROR, "Listen failed with error code %d\n", errno);
		closelog();
		exit(EXIT_FAILURE);
	}
#if !(USE_AESD_CHAR_DEVICE)
	// Set up signal handler for SIGALRM
	struct sigaction sa;
	sa.sa_handler = timer_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGALRM, &sa, NULL) == -1)
	{
		syslog(LOG_PERROR, "Unable to set up signal handler for SIGALRM with error code %d\n", errno);
		closelog();
		exit(EXIT_FAILURE);
	}

	// Create and start the timer
	timer_t timerid;
	struct sigevent sev;
	struct itimerspec its;

	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = SIGALRM;
	sev.sigev_value.sival_ptr = &timerid;
	if (timer_create(CLOCK_REALTIME, &sev, &timerid) == -1)
	{
		syslog(LOG_PERROR, "timer_create failed with error code %d\n", errno);
		closelog();
		exit(EXIT_FAILURE);
	}

	its.it_value.tv_sec = 10;
	its.it_value.tv_nsec = 0;
	its.it_interval.tv_sec = 10;
	its.it_interval.tv_nsec = 0;
	if (timer_settime(timerid, 0, &its, NULL) == -1)
	{
		syslog(LOG_PERROR, "timer_settime failed with error code %d\n", errno);
		closelog();
		exit(EXIT_FAILURE);
	}
#endif	

	// Accept and handle incoming connections
	while (!signal_detected)
	{
		struct sockaddr_in client_addr;
		socklen_t client_addr_size = sizeof(client_addr);

		// Accept connection
		int client_fd = accept(socket_fd, (struct sockaddr *)&client_addr, &client_addr_size);
		if (client_fd == -1)
		{
			syslog(LOG_PERROR, "Accept failed with error code %d\n", errno);
			continue;
		}

		// Convert client IP to string
		char ip_addr[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &client_addr.sin_addr, ip_addr, INET_ADDRSTRLEN);

		syslog(LOG_DEBUG, "Accepted connection from %s\n", ip_addr);

		// Create thread data
		struct thread_data_t *thread_data = malloc(sizeof(struct thread_data_t));
		if (thread_data == NULL)
		{
			syslog(LOG_PERROR, "Failed to allocate memory for thread data\n");
			close(client_fd);
			continue;
		}

		// Initialize thread data
		thread_data->client_fd = client_fd;
		thread_data->is_socket_complete = false;

		// Create thread to handle client
		pthread_t thread;
		if (pthread_create(&thread, NULL, handle_client, thread_data) != 0)
		{
			syslog(LOG_PERROR, "Thread creation failed with error code %d\n", errno);
			close(client_fd);
			free(thread_data);
			continue;
		}

		// Update thread data
		thread_data->thread_id = thread;

		// Add thread data to the list
		SLIST_INSERT_HEAD(&thread_data_head, thread_data, entries);

		// Clean up completed threads
		struct thread_data_t *temp, *next;
		SLIST_FOREACH_SAFE(temp, &thread_data_head, entries, next)
		{
			if (temp->is_socket_complete)
			{
				pthread_join(temp->thread_id, NULL);
				SLIST_REMOVE(&thread_data_head, temp, thread_data_t, entries);
				free(temp);
			}
		}
	}

	// Clean up remaining threads
	struct thread_data_t *temp;
	while (!SLIST_EMPTY(&thread_data_head))
	{
		temp = SLIST_FIRST(&thread_data_head);
		close(temp->client_fd);
		pthread_join(temp->thread_id, NULL);
		SLIST_REMOVE_HEAD(&thread_data_head, entries);
		free(temp);
	}

	// Close sockets and files
	close(socket_fd);
	// close(fd);

	
#if !(USE_AESD_CHAR_DEVICE)
	pthread_mutex_destroy(&aesdsocket_mutex);
	timer_delete(timerid);
	int ret = remove(filename);
	if (ret == 0)
	{
		syslog(LOG_DEBUG, "Deleted file %s\n", filename);
	}
	else
	{
		syslog(LOG_PERROR, "Unable to delete file %s with error code %d\n", filename, errno);
	}
#endif

	syslog(LOG_DEBUG, "Process Completed\n");
	closelog();
	exit(EXIT_SUCCESS);
}

void daemonize(void)
{

	int pid = fork();
	if (pid < 0)
	{
		perror("Fork Failed\n");
		exit(-1);
	}
	if (pid > 0)
	{
		exit(EXIT_SUCCESS);
	}

	int sid = setsid();
	if (sid < 0)
	{
		perror("setsid failed");
	}

	if (chdir("/") < 0)
	{

		perror("chdir failed\n");
		exit(-1);
	}

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	int var_daemon = open("/dev/null", O_RDWR);
	if (var_daemon < 0)
	{
		perror("file redirection failed");
		exit(-1);
	}
	dup2(var_daemon, STDIN_FILENO);
	dup2(var_daemon, STDOUT_FILENO);
	dup2(var_daemon, STDERR_FILENO);
	close(var_daemon);
}

