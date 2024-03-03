#include <stdlib.h>
#include <string.h>
#include <stdio.h>
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

#define FILE_SIZE 8192
#define MAX_CONNECTIONS 30

int socket_fd, client_fd;
pthread_mutex_t aesdsocket_mutex;
pthread_t aesdsocket_threads[MAX_CONNECTIONS];
int thread_count = 0;
volatile bool signal_detected = false;
char file_array[FILE_SIZE];
struct sockaddr_in client_addr;
char ip_addr[INET6_ADDRSTRLEN];
time_t t;
struct tm *tmp;
char MY_TIME[50];
// int fd;

struct thread_data_t
{
	int client_fd;
	pthread_t thread_id;
	bool is_socket_complete;
	int file_fd;
	SLIST_ENTRY(thread_data_t)
	entries;
};

void daemonize(void);
char filename[] = "/var/tmp/aesdsocketdata";

void mysig(int signo)
{
	if (signo == SIGINT || signo == SIGTERM)
	{
		signal_detected = true;
	}
}

void *handle_client(void *arg)
{
    struct thread_data_t *data = (struct thread_data_t *)arg;
    syslog(LOG_DEBUG, "Receive Started\n");

    int fd = open(filename, O_RDWR | O_CREAT | O_APPEND, S_IRWXU | S_IRWXG | S_IRWXO);
    if (fd == -1)
    {
        syslog(LOG_PERROR, "Error opening or creating the file %s with error code %d\n", filename, errno);
        close(data->client_fd);
        data->is_socket_complete = false;
        return NULL;
    }

    int bytes_rec;
    bool rec_complete = false;
    char *ptr = NULL;

    while (!rec_complete)
    {
        bytes_rec = recv(data->client_fd, file_array, FILE_SIZE, 0);
        if (bytes_rec < 0)
        {
            syslog(LOG_PERROR, "Receive unsuccessful with error code %d\n", errno);
            close(data->client_fd);
            data->is_socket_complete = false;
            break;
        }

        ptr = memchr(file_array, '\n', bytes_rec);
        if (ptr != NULL)
        {
            rec_complete = true;
        }

        if (pthread_mutex_lock(&aesdsocket_mutex) != 0)
        {
            syslog(LOG_PERROR, "Mutex Lock Failed with error code %d\n", errno);
            close(data->client_fd);
            data->is_socket_complete = false;
            break;
        }

        ssize_t result = write(fd, file_array, bytes_rec);
        pthread_mutex_unlock(&aesdsocket_mutex);

        if (result == -1)
        {
            syslog(LOG_PERROR, "Unable to write to the file %s with error code %d\n", filename, errno);
            close(data->client_fd);
            data->is_socket_complete = false;
            break;
        }
    }

    if (lseek(fd, 0, SEEK_SET) == -1)
    {
        syslog(LOG_PERROR, "Unable to reset the file pointer of file %s with error code %d\n", filename, errno);
        close(data->client_fd);
        data->is_socket_complete = false;
        close(fd);
        return NULL;
    }

    syslog(LOG_DEBUG, "Sending Started\n");
    int bytes_send;
    bool send_complete = false;

    while (!send_complete && rec_complete)
    {
        bytes_send = read(fd, file_array, FILE_SIZE);
        if (bytes_send < 0)
        {
            syslog(LOG_PERROR, "Error in reading data from the file for sending\n");
            close(data->client_fd);
            data->is_socket_complete = false;
            break;
        }
        else if (bytes_send == 0)
        {
            send_complete = true;
            rec_complete = false;
            data->is_socket_complete = true;
            break;
        }

        int sent_actual = send(data->client_fd, file_array, bytes_send, 0);
        if (sent_actual != bytes_send)
        {
            syslog(LOG_PERROR, "Error in sending data to socket\n");
            close(data->client_fd);
            data->is_socket_complete = false;
            break;
        }
    }

    close(fd);
    close(data->client_fd);
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
	strftime(MY_TIME, sizeof(MY_TIME), "timestamp: %Y %m %d %H:%M:%S\n", tmp); // Corrected the format specifier for month (use %m instead of %M)

	int fd = open(filename, O_RDWR | O_CREAT | O_APPEND, S_IRWXU | S_IRWXG | S_IRWXO);

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

	// Initialize mutex
	if (pthread_mutex_init(&aesdsocket_mutex, NULL) != 0)
	{
		syslog(LOG_PERROR, "Mutex initialization failed\n");
		closelog();
		exit(EXIT_FAILURE);
	}

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

	// Listen for connections
	errorcode = listen(socket_fd, 50);
	if (errorcode == -1)
	{
		close(socket_fd);
		syslog(LOG_PERROR, "Listen failed with error code %d\n", errno);
		closelog();
		exit(EXIT_FAILURE);
	}

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

	// Remove temporary file
	int ret = remove(filename);
	if (ret == 0)
	{
		syslog(LOG_DEBUG, "Deleted file %s\n", filename);
	}
	else
	{
		syslog(LOG_PERROR, "Unable to delete file %s with error code %d\n", filename, errno);
	}

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