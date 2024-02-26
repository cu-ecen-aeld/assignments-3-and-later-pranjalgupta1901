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

#define FILE_SIZE 1024
int socket_fd, client_fd;
void daemonize(void);
char filename[] = "/var/tmp/aesdsocketdata";
void mysig(int signo)
{
	if (signo == SIGINT || signo == SIGTERM)
	{
		close(socket_fd);
		close(client_fd);

		int ret = remove(filename);

		if (ret == 0)
		{
			syslog(LOG_DEBUG, "Deleted file %s\n", filename);
		}
		else
		{
			syslog(LOG_PERROR, "Unable to Delete file %s with error code %d  \n", filename, errno);
		}
		closelog();
		exit(EXIT_SUCCESS);
	}
}
void setup_signal()
{

	struct sigaction sa;

	sa.sa_handler = &mysig;
	sigemptyset(&(sa.sa_mask));
	sa.sa_flags = 0;
	if (sigaction(SIGINT, &sa, NULL) == -1)
	{
		close(socket_fd);
		close(client_fd);
		syslog(LOG_PERROR, "Unable to initialise SIGINT the signals with error code %d\n", errno);
		exit(-1);
	}

	if (sigaction(SIGTERM, &sa, NULL) == -1)
	{
		close(socket_fd);
		close(client_fd);
		syslog(LOG_PERROR, "Unable to initialise SIGTERM the signals with error code %d\n", errno);
		exit(-1);
	}
}

int main(int argc, char *argv[])
{

	struct addrinfo hints, *result;
	struct sockaddr *addr6;

	int errorcode;
	int var = 0;
	const char *port = "9000";
	char file_array[FILE_SIZE];
	char ip_addr[INET6_ADDRSTRLEN];

	openlog("aesdsocket", LOG_CONS | LOG_PID, LOG_USER);
	memset(&hints, 0, sizeof(hints));

	setup_signal();

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

	if (argc > 1 && strcmp(argv[1], "-d") == 0)
	{
		syslog(LOG_USER, "Daemonizing process\n");
		daemonize();
	}

	errorcode = bind(socket_fd, result->ai_addr, result->ai_addrlen); // check what should be the sockaddr for it?
	if (errorcode == -1)
	{
		close(socket_fd);
		syslog(LOG_PERROR, "Socket bind failed with error code %d and closing server socket \n", errno);
		closelog();
		exit(-1);
	}

	syslog(LOG_DEBUG, "Bind Successful\n");
	freeaddrinfo(result);

	errorcode = listen(socket_fd, 10);
	if (errorcode == -1)
	{
		close(socket_fd);
		syslog(LOG_PERROR, "Listen failed with error code %d and closing server socket \n", errno);
		closelog();
		exit(-1);
	}

	struct sockaddr_in client_addr;
	socklen_t client_addr_size = sizeof(client_addr);

	while (1)
	{
		client_fd = accept(socket_fd, (struct sockaddr *)&client_addr, &client_addr_size);
		if (client_fd == -1)
		{
			close(socket_fd);
			syslog(LOG_PERROR, "connection failed with error code %d and closing server socket \n", errno);
			closelog();
		}

		else
		{
			struct sockaddr_in *ip_addr_ptr = (struct sockaddr_in *)&client_addr;

			inet_ntop(AF_INET, &ip_addr_ptr->sin_addr, ip_addr, INET_ADDRSTRLEN);

			syslog(LOG_DEBUG, "Accepted connection from %s\n", ip_addr);

			int fd;
			fd = open(filename, O_RDWR | O_CREAT | O_APPEND, S_IRWXU | S_IRWXG | S_IRWXO);

			if (fd == -1)
			{
				syslog(LOG_DEBUG, "Closed connection from %s\n", ip_addr);
				close(client_fd);
				syslog(LOG_PERROR, "Error in opening of the file %s and with error code %d\n", filename, errno);
			}
			else
			{

				syslog(LOG_DEBUG, "Recieve Started\n");

				int bytes_rec;
				bool rec_complete = false;
				char *ptr = NULL;
				while (rec_complete == false)
				{

					bytes_rec = recv(client_fd, file_array, FILE_SIZE, 0);
					if (bytes_rec < 0)
					{
						syslog(LOG_DEBUG, "Closed connection from %s\n", ip_addr);
						close(client_fd);
						syslog(LOG_PERROR, "recieve unsuccessful with error code %d\n", errno);
						closelog();
					}
					else
					{
						ssize_t result = write(fd, file_array, bytes_rec);

						if (result == -1)
						{
							syslog(LOG_DEBUG, "Closed connection from %s\n", ip_addr);
							close(client_fd);
							syslog(LOG_PERROR, "Unable to write to the file %s with error code %d\n", filename, errno);
							closelog();
						}
						else
						{
							ptr = memchr(file_array, '\n', bytes_rec);
							if (ptr != NULL)
							{
								rec_complete = true;
								break;
							}
						}
					}
				}

				int file_offset = lseek(fd, 0, SEEK_SET);
				if (file_offset == -1)
				{
					syslog(LOG_DEBUG, "Closed connection from %s\n", ip_addr);
					syslog(LOG_PERROR, "Unable to reset the file pointer of file %s with error code %d\n", filename, errno);
					close(client_fd);
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
							close(client_fd);
							perror("error in sending data to socket\n");
						}
						else if (bytes_send == 0)
						{
							close(client_fd);
							send_complete = true;
							rec_complete = false;
						}
						else
						{
							sent_actual = send(client_fd, file_array, bytes_send, 0);
							if (sent_actual != bytes_send)
							{
								close(client_fd);
								perror("error in sending data to socket");
							}
						}
					}
				}
			}
		}
	}
	syslog(LOG_DEBUG, "Process Completed\n");
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
	printf("Child process is created\n");

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
