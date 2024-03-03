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
#include <sys/queue.h>

#define FILE_SIZE 1024
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

struct thread_data_t
{
	int client_fd;
	pthread_t thread_id;
	bool is_socket_complete;
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
	int fd;

	syslog(LOG_DEBUG, "Recieve Started\n");

	int bytes_rec;
	bool rec_complete = false;
	char *ptr = NULL;
	while (rec_complete == false)
	{

		bytes_rec = recv(data->client_fd, file_array, FILE_SIZE, 0);
		if (bytes_rec < 0)
		{
			syslog(LOG_DEBUG, "Closed connection from %s\n", ip_addr);
			close(data->client_fd);
			syslog(LOG_PERROR, "recieve unsuccessful with error code %d\n", errno);
			closelog();
		}
		else
		{
			fd = open(filename, O_RDWR | O_CREAT | O_APPEND, S_IRWXU | S_IRWXG | S_IRWXO);

			if (fd == -1)
			{
				syslog(LOG_DEBUG, "Closed connection from %s\n", ip_addr);
				close(data->client_fd);
				// pthread_mutex_unlock(&aesdsocket_mutex);
				syslog(LOG_PERROR, "Error in opening of the file %s and with error code %d\n", filename, errno);
				return NULL;
			}

			ptr = memchr(file_array, '\n', bytes_rec);
			if (ptr != NULL)
			{
				rec_complete = true;
			}
			if (pthread_mutex_lock(&aesdsocket_mutex) != 0)
			{
				syslog(LOG_DEBUG, "Closed connection from %s\n", ip_addr);
				close(data->client_fd);
				syslog(LOG_PERROR, "Mutex Lock Failed with error code %d\n", errno);
				closelog();
			}
			ssize_t result = write(fd, file_array, bytes_rec);

			if (result == -1)
			{
				syslog(LOG_DEBUG, "Closed connection from %s\n", ip_addr);
				close(data->client_fd);
				// close(fd);
				syslog(LOG_PERROR, "Unable to write to the file %s with error code %d\n", filename, errno);
				closelog();
			}
			pthread_mutex_unlock(&aesdsocket_mutex);
		}
	}

	int file_offset = lseek(fd, 0, SEEK_SET);
	if (file_offset == -1)
	{
		syslog(LOG_DEBUG, "Closed connection from %s\n", ip_addr);
		syslog(LOG_PERROR, "Unable to reset the file pointer of file %s with error code %d\n", filename, errno);
		close(data->client_fd);
	}
	else
	{

		syslog(LOG_DEBUG, "Sending Started\n");
		int bytes_send;
		int sent_actual;
		bool send_complete = false;

		while (send_complete == false && rec_complete == true)
		{
			bytes_send = read(fd, file_array, FILE_SIZE);
			if (bytes_send < 0)
			{
				close(data->client_fd);
				perror("error in sending data to socket\n");
			}
			else if (bytes_send == 0)
			{
				close(data->client_fd);
				send_complete = true;
				rec_complete = false;
			}
			else
			{
				sent_actual = send(client_fd, file_array, bytes_send, 0);
				if (sent_actual != bytes_send)
				{
					close(data->client_fd);
					perror("error in sending data to socket");
				}
			}
		}
	}
	// close(fd);
	data->is_socket_complete = true;
	// return arg;
}

void setup_signal()
{
	struct sigaction sa;

	sa.sa_handler = &mysig;
	sigemptyset(&(sa.sa_mask));
	sa.sa_flags = 0;
	if (sigaction(SIGINT, &sa, NULL) == -1)
	{
		syslog(LOG_PERROR, "Unable to initialise SIGINT the signals with error code %d\n", errno);
		exit(-1);
	}

	if (sigaction(SIGTERM, &sa, NULL) == -1)
	{

		syslog(LOG_PERROR, "Unable to initialise SIGTERM the signals with error code %d\n", errno);
		exit(-1);
	}
}

void timer_handler(int signum)
{
	time(&t);
	tmp = localtime(&t);

	// using strftime to convert time structure to string
	strftime(MY_TIME, sizeof(MY_TIME), "timestamp: %Y %M %d %H:%M:%S\n", tmp);


	int fd = open(filename, O_RDWR | O_CREAT | O_APPEND, S_IRWXU | S_IRWXG | S_IRWXO);

	if (fd == -1)
	{
		// pthread_mutex_unlock(&aesdsocket_mutex);
		syslog(LOG_PERROR, "Error in opening or creating the file %s with error code %d\n", filename, errno);
		return;
	}

	// Convert time string to bytes for writing to file
	size_t time_length = strlen(MY_TIME);
		// Locking mutex to ensure thread safety
	if (pthread_mutex_lock(&aesdsocket_mutex) != 0)
	{
		syslog(LOG_PERROR, "Mutex Lock Failed with error code %d\n", errno);
		return;
	}
	ssize_t result = write(fd, MY_TIME, time_length);

	if (result == -1)
	{
		syslog(LOG_PERROR, "Unable to write to the file %s with error code %d\n", filename, errno);
	}
pthread_mutex_unlock(&aesdsocket_mutex);
	// close(fd);
	// Unlock mutex
}

int main(int argc, char *argv[])
{

	struct addrinfo hints, *result;
	struct sockaddr *addr6;

	int errorcode;
	int var = 0;
	const char *port = "9000";
	char file_array[FILE_SIZE];

	openlog("aesdsocket_assign_6", LOG_CONS | LOG_PID, LOG_USER);

	memset(&hints, 0, sizeof(hints));

	if (pthread_mutex_init(&aesdsocket_mutex, NULL) != 0)
	{
		return -1;
	}

	setup_signal();
	SLIST_HEAD(thread_data_head, thread_data_t) 	thread_data_head;
	SLIST_INIT(&thread_data_head);

	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	errorcode = getaddrinfo(NULL, port, &hints, &result);
	if (errorcode != 0)
	{
		syslog(LOG_PERROR, "Error in gettng address suing getaddrinfo with error code %d\n", errno);
		closelog();
		exit(-1);
	}

	socket_fd = socket(result->ai_family, result->ai_socktype, 0);
	if (socket_fd == -1)
	{
		syslog(LOG_PERROR, "socket creation failed with error code %d\n", errno);
		closelog();
		exit(-1);
	}
	syslog(LOG_DEBUG, "Socket Created with Socket Id %d\n", socket_fd);

	int var_setsockopt = 1;
	if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &var_setsockopt,
				   sizeof(int)) == -1)
	{
		syslog(LOG_PERROR, "Socket resuse address failed with error code %d\n", errno);
		closelog();
		exit(-1);
	}

	errorcode = bind(socket_fd, result->ai_addr, result->ai_addrlen); // check what should be the sockaddr for it?
	if (errorcode == -1)
	{
		close(socket_fd);
		syslog(LOG_PERROR, "Socket bind failed with error code %d and closing server socket \n", errno);
		closelog();
		exit(-1);
	}

	if (argc > 1 && strcmp(argv[1], "-d") == 0)
	{
		syslog(LOG_USER, "Daemonizing process\n");
		daemonize();
	}

	syslog(LOG_DEBUG, "Bind Successful\n");
	freeaddrinfo(result);

	errorcode = listen(socket_fd, 50);
	if (errorcode == -1)
	{
		close(socket_fd);
		syslog(LOG_PERROR, "Listen failed with error code %d and closing server socket \n", errno);
		closelog();
		exit(-1);
	}

	struct sigaction sa;
	sa.sa_handler = timer_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	if (sigaction(SIGALRM, &sa, NULL) == -1)
	{
		syslog(LOG_PERROR, "Unable to set up signal handler for SIGALRM with error code %d\n", errno);
		closelog();
		exit(-1);
	}

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
		exit(-1);
	}

	socklen_t client_addr_size = sizeof(client_addr);

	while (!signal_detected)
	{
		struct thread_data_t *thread_data;
		client_fd = accept(socket_fd, (struct sockaddr *)&client_addr, &client_addr_size);
		if (client_fd == -1)
		{
			syslog(LOG_PERROR, "connection failed with error code %d and closing server socket \n", errno);
			closelog();
		}

		else
		{
			struct sockaddr_in *ip_addr_ptr = (struct sockaddr_in *)&client_addr;

			inet_ntop(AF_INET, &ip_addr_ptr->sin_addr, ip_addr, INET_ADDRSTRLEN);

			syslog(LOG_DEBUG, "Accepted connection from %s\n", ip_addr);

			thread_data = (struct thread_data_t *)(malloc(sizeof(struct thread_data_t)));
			if (thread_data == NULL)
			{
				syslog(LOG_PERROR, "Not enough memory remaining\n");
				// close(client_fd);
			}
			else
			{

				pthread_t thread;
				if (pthread_create(&thread, NULL, handle_client, thread_data) != 0)
				{
					// close(socket_fd);
					syslog(LOG_PERROR, "Thread Creating Failed with error code %d\n", errno);
					closelog();
				}
				else
				{
					thread_data->client_fd = client_fd;
					thread_data->is_socket_complete = false;
					thread_data->thread_id = thread;
					SLIST_INSERT_HEAD(&thread_data_head, thread_data, entries);
				}
			}
		}
	}

	// freeing all the linked list as the signal is detected

	while (!SLIST_EMPTY(&thread_data_head))
	{
		struct thread_data_t *temp = SLIST_FIRST(&thread_data_head);
		close(temp->client_fd);
		pthread_join(temp->thread_id, NULL);
		SLIST_REMOVE_HEAD(&thread_data_head, entries);
		free(temp);
	}

	close(socket_fd);
	// close(client_fd);

	int ret = remove(filename);

	if (ret == 0)
	{
		syslog(LOG_DEBUG, "Deleted file %s\n", filename);
	}
	else
	{
		syslog(LOG_PERROR, "Unable to Delete file %s with error code %d  \n", filename, errno);
	}

	syslog(LOG_DEBUG, "Process Completed\n");
	closelog();
	exit(EXIT_SUCCESS);
	return 0;
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
