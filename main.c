#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
 
#define SERVER_CERT		"server.crt"
#define SERVER_KEY		"server.key"

#define BUFFER_LEN		17000

struct sys_state {
	SSL_CTX		* ctx;
};

struct session {
	int			net_port;
	
	int			net_fd;
	SSL_CTX		* ctx;
	SSL			* ssl;
	int			ssl_read_again;
	int			ssl_write_again;
	int			ssl_accept_again;
	
	int			ssl_want_write;
	int			ssl_want_read;
	
	int			ssl_last_err;

	char *		buffer_read;
	size_t		buffer_read_len;
	char *		buffer_write;
	size_t		buffer_write_len;
};


void ssl_init(struct sys_state * s) {
	SSL_METHOD      * meth;

	SSL_library_init();
	SSL_load_error_strings();
	meth = TLSv1_server_method();
	s->ctx = SSL_CTX_new(meth);

	if (!s->ctx) {
			// errror
	}
}

void ssl_load_cert_key(struct sys_state * s, const char * cert, const char * key) {
	if (SSL_CTX_use_certificate_file(s->ctx, cert, SSL_FILETYPE_PEM) <= 0) {
	}
	if (SSL_CTX_use_PrivateKey_file(s->ctx, key, SSL_FILETYPE_PEM) <= 0) {
	}
	if (!SSL_CTX_check_private_key(s->ctx)) {
	}
}

void ssl_accept_connection(struct sys_state * ss, struct session ** s, size_t * sl, int sock) {
	struct sockaddr_in sa_cli;
	size_t client_len;
	client_len = sizeof(sa_cli);

	*(s) = (struct session *) realloc(*s, ++(*sl) * sizeof (struct session));

	/* Socket for a TCP/IP connection is created */
	(*s)[(*sl) - 1].net_fd = accept(sock, (struct sockaddr *)&sa_cli, &client_len);

	fcntl((*s)[(*sl) - 1].net_fd, F_SETFL, fcntl((*s)[(*sl) - 1].net_fd, F_GETFL, 0) | O_NONBLOCK);

	printf ("Connection from %lx, port %x\n", sa_cli.sin_addr.s_addr, sa_cli.sin_port);

	(*s)[(*sl) - 1].ssl = SSL_new(ss->ctx);
	SSL_set_fd((*s)[(*sl) - 1].ssl, (*s)[(*sl) - 1].net_fd);

	(*s)[(*sl) - 1].buffer_read = (char *) malloc(BUFFER_LEN * sizeof(char));
	(*s)[(*sl) - 1].buffer_read_len = 0;
	(*s)[(*sl) - 1].buffer_write = (char *) malloc(BUFFER_LEN * sizeof(char));
	(*s)[(*sl) - 1].buffer_write_len = 0;

/*
	strcpy((*s)[(*sl) - 1].buffer_write, "This message is from the SSL server");
	(*s)[(*sl) - 1].buffer_write_len = strlen("This message is from the SSL server");
*/
	(*s)[(*sl) - 1].ssl_accept_again = 0;
	(*s)[(*sl) - 1].ssl_read_again = 0;
	(*s)[(*sl) - 1].ssl_write_again = 0;
	(*s)[(*sl) - 1].ssl_want_write = 0;
	(*s)[(*sl) - 1].ssl_want_read = 0;

	(*s)[(*sl) - 1].ssl_last_err = SSL_accept((*s)[(*sl) - 1].ssl);
	printf("Initial SSL_accept\n");
	if ((*s)[(*sl) - 1].ssl_last_err <= 0) {
		if (SSL_ERROR_WANT_WRITE == SSL_get_error((*s)[(*sl) - 1].ssl, (*s)[(*sl) - 1].ssl_last_err)) {
			(*s)[(*sl) - 1].ssl_accept_again = 1;
			(*s)[(*sl) - 1].ssl_want_write = 1;
			(*s)[(*sl) - 1].ssl_want_read = 0;
			printf("Initial SSL_accept: got want write\n");
		}
		if (SSL_ERROR_WANT_READ == SSL_get_error((*s)[(*sl) - 1].ssl, (*s)[(*sl) - 1].ssl_last_err)) {
			(*s)[(*sl) - 1].ssl_accept_again = 1;
			(*s)[(*sl) - 1].ssl_want_read = 1;
			(*s)[(*sl) - 1].ssl_want_write = 0;
			printf("Initial SSL_accept: got want read\n");
		}
	}
}

void ssl_shutdown_connection(struct session * s) {
	printf("Closing at ZERO_RETURN\n");
	SSL_shutdown(s->ssl);
	close(s->net_fd);
	SSL_free(s->ssl);
}


int main(void)
{
	int	err;
	int		listen_sock;
	int		sock;
	struct sockaddr_in	sa_serv;
	char	*str;
	char	buf[4096];
	struct sys_state ss;
	struct session * sessions = NULL;
	size_t sessions_count = 0;
	short int	s_port = 5555;
	size_t i;
	fd_set rfds, wfds, efds;
	int maxfd = 0, retval;
	int size, k, j;

	struct timeval tv;
	ssl_init(&ss);
	ssl_load_cert_key(&ss, SERVER_CERT, SERVER_KEY);

	listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);   

	memset (&sa_serv, 0, sizeof(sa_serv));
	sa_serv.sin_family		= AF_INET;
	sa_serv.sin_addr.s_addr	= INADDR_ANY;
	sa_serv.sin_port		= htons (s_port);          /* Server Port number */
	err = bind(listen_sock, (struct sockaddr *)&sa_serv, sizeof(sa_serv));
 
	err = listen(listen_sock, 5);                    

	while (1) {
		tv.tv_sec = 4;
		tv.tv_usec = 0;
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		FD_ZERO(&efds);
 
		FD_SET(listen_sock, &rfds);
		maxfd = listen_sock;

		for (i = 0; i < sessions_count; ++i) {

			FD_SET(sessions[i].net_fd, &rfds);
			FD_SET(sessions[i].net_fd, &efds);
			if (sessions[i].ssl_want_write == 1 || (sessions[i].buffer_write_len > 0))
				FD_SET(sessions[i].net_fd, &wfds);
			if (sessions[i].net_fd > maxfd)
				maxfd = sessions[i].net_fd;

			if ((size = SSL_pending(sessions[i].ssl)) > 0) {
				sessions[i].ssl_last_err = SSL_read(sessions[i].ssl,
					sessions[i].buffer_read + sessions[i].buffer_read_len,
					((sizeof( *(sessions[i].buffer_read) ) - sessions[i].buffer_read_len) > size) ?
						(sizeof( *(sessions[i].buffer_read) ) - sessions[i].buffer_read_len) : 
						size);
				if (sessions[i].ssl_last_err > 0) {
					sessions[i].buffer_read_len += sessions[i].ssl_last_err;
				}
			}

			if (sessions[i].buffer_read_len > 0) {
				printf("Got: '");
				for (k = 0; k < sessions[i].buffer_read_len; ++k)
					printf("%c", sessions[i].buffer_read[k]);
				printf("'\n");
				sessions[i].buffer_read_len = 0;
			}
		}
 
		retval = select(maxfd + 1, &rfds, &wfds, &efds, &tv);

		if (retval > 0) {
			if (FD_ISSET(listen_sock, &rfds)) {
				ssl_accept_connection(&ss, &sessions, &sessions_count, listen_sock);
				continue;
			}

			for (i = 0; i < sessions_count; ++i) {
				if (FD_ISSET(sessions[i].net_fd, &rfds) || FD_ISSET(sessions[i].net_fd, &wfds)) {

					if (FD_ISSET(sessions[i].net_fd, &efds)) {
						ssl_shutdown_connection(&sessions[i]);

						if (i < (sessions_count - 1))
							memmove(sessions + i, sessions + i + 1, sizeof (struct session) * (sessions_count - i - 1));
						sessions_count--;
						break;
					}
					/* 0 */
					if (
						(sessions[i].ssl_accept_again == 1) && 
						(
							(FD_ISSET(sessions[i].net_fd, &rfds) && (sessions[i].ssl_want_read == 1)) ||
							(FD_ISSET(sessions[i].net_fd, &wfds) && (sessions[i].ssl_want_write == 1))
						)
					) {
						printf("SSL_accept again\n");
						sessions[i].ssl_last_err = SSL_accept(sessions[i].ssl);
						if (sessions[i].ssl_last_err <= 0) {
							if (SSL_ERROR_WANT_WRITE == SSL_get_error(sessions[i].ssl, sessions[i].ssl_last_err)) {
								sessions[i].ssl_accept_again = 1;
								sessions[i].ssl_want_write = 1;
								sessions[i].ssl_want_read = 0;
								printf("SSL_accept again: got want write\n");
								continue;
							}
							if (SSL_ERROR_WANT_READ == SSL_get_error(sessions[i].ssl, sessions[i].ssl_last_err)) {
								sessions[i].ssl_accept_again = 1;
								sessions[i].ssl_want_read = 1;
								sessions[i].ssl_want_write = 0;
								printf("SSL_accept again: got want read\n");
								continue;
							}
						} else {
							sessions[i].ssl_accept_again = 0;
							sessions[i].ssl_want_write = 0;
							sessions[i].ssl_want_read = 0;
							printf("SSL_accept again: got ok\n");
						}
					}
					/* 1 */
					if (
						(sessions[i].ssl_read_again == 1) && 
						(
							(FD_ISSET(sessions[i].net_fd, &rfds) && (sessions[i].ssl_want_read == 1)) ||
							(FD_ISSET(sessions[i].net_fd, &wfds) && (sessions[i].ssl_want_write == 1))
						)
					) {
						printf("SSL_read again\n");
						sessions[i].ssl_last_err = SSL_read(sessions[i].ssl,
							sessions[i].buffer_read + sessions[i].buffer_read_len,
							sizeof( *(sessions[i].buffer_read) ) - sessions[i].buffer_read_len);
						if (sessions[i].ssl_last_err > 0) {
							sessions[i].ssl_read_again = 0;
							sessions[i].ssl_want_write = 0;
							sessions[i].ssl_want_read = 0;
							sessions[i].buffer_read_len += err;
							printf("SSL_read again: got finish\n");
						} else {
							if (SSL_ERROR_WANT_WRITE == SSL_get_error(sessions[i].ssl, sessions[i].ssl_last_err)) {
								sessions[i].ssl_read_again = 1;
								sessions[i].ssl_want_write = 1;
								sessions[i].ssl_want_read = 0;
								printf("SSL_read again: got want write\n");
								continue;
							}
							if (SSL_ERROR_WANT_READ == SSL_get_error(sessions[i].ssl, sessions[i].ssl_last_err)) {
								sessions[i].ssl_read_again = 1;
								sessions[i].ssl_want_read = 1;
								sessions[i].ssl_want_write = 0;
								printf("SSL_read again: got want read\n");
								continue;
							}
							if (SSL_ERROR_ZERO_RETURN == SSL_get_error(sessions[i].ssl, sessions[i].ssl_last_err) || SSL_ERROR_SYSCALL == SSL_get_error(sessions[i].ssl, sessions[i].ssl_last_err)) {
								ssl_shutdown_connection(&sessions[i]);

								if (i < (sessions_count - 1))
									memmove(sessions + i, sessions + i + 1, sizeof (struct session) * (sessions_count - i - 1));
									sessions_count--;
								break;
							}
						}
					}
					/* 2 */
					if (
						(sessions[i].ssl_write_again == 1) && 
						(
							(FD_ISSET(sessions[i].net_fd, &rfds) && (sessions[i].ssl_want_read == 1)) ||
							(FD_ISSET(sessions[i].net_fd, &wfds) && (sessions[i].ssl_want_write == 1))
						)
					) {
						printf("SSL_write again\n");
						sessions[i].ssl_last_err = SSL_write(sessions[i].ssl, sessions[i].buffer_write, sessions[i].buffer_write_len);
						if (sessions[i].ssl_last_err > 0) {
							sessions[i].ssl_read_again = 0;
							sessions[i].ssl_want_write = 0;
							sessions[i].ssl_want_read = 0;
							memmove(sessions[i].buffer_write, sessions[i].buffer_write + sessions[i].ssl_last_err, sessions[i].buffer_write_len - sessions[i].ssl_last_err);
							sessions[i].buffer_write_len =- sessions[i].ssl_last_err;
							printf("SSL_write again: got ok\n");
						} else {
							if (SSL_ERROR_WANT_WRITE == SSL_get_error(sessions[i].ssl, sessions[i].ssl_last_err)) {
								sessions[i].ssl_read_again = 1;
								sessions[i].ssl_want_write = 1;
								sessions[i].ssl_want_read = 0;
								printf("SSL_write again: got want write\n");
								continue;
							}
							if (SSL_ERROR_WANT_READ == SSL_get_error(sessions[i].ssl, sessions[i].ssl_last_err)) {
								sessions[i].ssl_read_again = 1;
								sessions[i].ssl_want_read = 1;
								sessions[i].ssl_want_write = 0;
								printf("SSL_write again: got want read\n");
								continue;
							}
						}
					}
					/* 4    have data to write ? */
					if ((sessions[i].buffer_write_len > 0) && FD_ISSET(sessions[i].net_fd, &wfds) && !(sessions[i].ssl_want_write == 1)) {
						 printf("SSL_write\n");
						 sessions[i].ssl_last_err = SSL_write(sessions[i].ssl, sessions[i].buffer_write, sessions[i].buffer_write_len);
						 if (sessions[i].ssl_last_err <= 0) {
							if (SSL_ERROR_WANT_WRITE == SSL_get_error(sessions[i].ssl, sessions[i].ssl_last_err)) {
								sessions[i].ssl_write_again = 1;
								sessions[i].ssl_want_write = 1;
								sessions[i].ssl_want_read = 0;
								 printf("SSL_writ: got write again\n");
								continue;
							}
							if (SSL_ERROR_WANT_READ == SSL_get_error(sessions[i].ssl, sessions[i].ssl_last_err)) {
								sessions[i].ssl_write_again = 1;
								sessions[i].ssl_want_read = 1;
								sessions[i].ssl_want_write = 0;
								 printf("SSL_write: got read again\n");
								continue;
							}
						 } else {
							sessions[i].ssl_write_again = 0;
							sessions[i].ssl_want_write = 0;
							sessions[i].ssl_want_read = 0;
							printf("SSL_write: got ok : written %d, was %d\n", err, sessions[i].buffer_write_len);
							if (sessions[i].ssl_last_err < sessions[i].buffer_write_len) {
								memmove(sessions[i].buffer_write, sessions[i].buffer_write + sessions[i].ssl_last_err, sessions[i].buffer_write_len - sessions[i].ssl_last_err);
								sessions[i].buffer_write_len -= sessions[i].ssl_last_err;
							} else
								sessions[i].buffer_write_len = 0;
						 }
					}
					/* 5 trigger reading if we got data from net */
					if (FD_ISSET(sessions[i].net_fd, &rfds) && !(sessions[i].ssl_want_read == 1)) {
						 printf("SSL_read trigger\n");
						sessions[i].ssl_last_err = SSL_read(sessions[i].ssl,
							sessions[i].buffer_read + sessions[i].buffer_read_len,
							sizeof( *(sessions[i].buffer_read) ) - sessions[i].buffer_read_len);
						if (sessions[i].ssl_last_err > 0) {
							sessions[i].ssl_read_again = 0;
							sessions[i].ssl_want_write = 0;
							sessions[i].ssl_want_read = 0;
							sessions[i].buffer_read_len += sessions[i].ssl_last_err;
							 printf("SSL_read trigger: got ok\n");
							
						} else {
							printf("%d\n", SSL_get_error(sessions[i].ssl, sessions[i].ssl_last_err));
							if (SSL_ERROR_WANT_WRITE == SSL_get_error(sessions[i].ssl, sessions[i].ssl_last_err)) {
								sessions[i].ssl_read_again = 1;
								sessions[i].ssl_want_write = 1;
								sessions[i].ssl_want_read = 0;
								 printf("SSL_read trigger: got write again\n");
								continue;
							}
							if (SSL_ERROR_WANT_READ == SSL_get_error(sessions[i].ssl, sessions[i].ssl_last_err)) {
								sessions[i].ssl_read_again = 1;
								sessions[i].ssl_want_read = 1;
								sessions[i].ssl_want_write = 0;
								 printf("SSL_read trigger: got read again\n");
								continue;
							}
							if (SSL_ERROR_ZERO_RETURN == SSL_get_error(sessions[i].ssl, sessions[i].ssl_last_err) || SSL_ERROR_SYSCALL == SSL_get_error(sessions[i].ssl, sessions[i].ssl_last_err)) {
								ssl_shutdown_connection(&sessions[i]);

								if (i < (sessions_count - 1))
									memmove(sessions + i, sessions + i + 1, sizeof (struct session) * (sessions_count - i - 1));
									sessions_count--;
								break;
							}
						}
					}
				}
			}
		}
	}
	/* Free the SSL_CTX structure */
	// SSL_CTX_free(ctx);
	return 0;
}
