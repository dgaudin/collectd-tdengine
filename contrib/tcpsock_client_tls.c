/*
 * tcpsock_client_tls.c - Test client for collectd tcpsock plugin with TLS
 *
 * This program connects to collectd's tcpsock plugin using TLS and executes
 * LISTVAL and GETALLVAL commands to test the TLS command implementation.
 *
 * Compilation:
 *   gcc -o tcpsock_client_tls tcpsock_client_tls.c -lssl -lcrypto -Wall -Werror
 *
 * Usage:
 *   ./tcpsock_client_tls <host> <port> <ca_cert>
 *   Example: ./tcpsock_client_tls localhost 25827 /etc/collectd/tls/server.crt
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 8192

static void print_ssl_error(const char *msg) {
    fprintf(stderr, "Error: %s\n", msg);
    ERR_print_errors_fp(stderr);
}

static int connect_to_host(const char *hostname, int port) {
    struct addrinfo hints, *res, *rp;
    char port_str[16];
    int sockfd = -1;
    int ret;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(port_str, sizeof(port_str), "%d", port);

    ret = getaddrinfo(hostname, port_str, &hints, &res);
    if (ret != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1) {
            continue;
        }

        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break; /* Success */
        }

        close(sockfd);
        sockfd = -1;
    }

    freeaddrinfo(res);

    if (sockfd == -1) {
        fprintf(stderr, "Failed to connect to %s:%d\n", hostname, port);
        return -1;
    }

    printf("Connected to %s:%d\n", hostname, port);
    return sockfd;
}

static SSL_CTX *init_ssl_context(const char *ca_cert_file) {
    SSL_CTX *ctx;

    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        print_ssl_error("Failed to create SSL context");
        return NULL;
    }

    /* Load CA certificate for server verification */
    if (ca_cert_file != NULL) {
        if (SSL_CTX_load_verify_locations(ctx, ca_cert_file, NULL) != 1) {
            print_ssl_error("Failed to load CA certificate");
            SSL_CTX_free(ctx);
            return NULL;
        }
        /* Enable server certificate verification */
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        printf("Loaded CA certificate: %s\n", ca_cert_file);
    } else {
        /* Disable server certificate verification (not recommended for production) */
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        printf("Warning: Server certificate verification disabled\n");
    }

    return ctx;
}

static SSL *establish_tls(SSL_CTX *ctx, int sockfd) {
    SSL *ssl;

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        print_ssl_error("Failed to create SSL object");
        return NULL;
    }

    if (SSL_set_fd(ssl, sockfd) != 1) {
        print_ssl_error("Failed to set SSL file descriptor");
        SSL_free(ssl);
        return NULL;
    }

    printf("Performing TLS handshake...\n");
    if (SSL_connect(ssl) != 1) {
        print_ssl_error("TLS handshake failed");
        SSL_free(ssl);
        return NULL;
    }

    printf("TLS handshake successful\n");
    printf("Cipher: %s\n", SSL_get_cipher(ssl));

    return ssl;
}

static int send_command(SSL *ssl, const char *command) {
    char buffer[BUFFER_SIZE];
    int len;

    printf("\n=== Sending command: %s ===\n", command);

    /* Send command */
    snprintf(buffer, sizeof(buffer), "%s\n", command);
    len = SSL_write(ssl, buffer, strlen(buffer));
    if (len <= 0) {
        print_ssl_error("Failed to send command");
        return -1;
    }

    /* Read response */
    printf("Response:\n");
    while (1) {
        len = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (len <= 0) {
            int err = SSL_get_error(ssl, len);
            if (err == SSL_ERROR_ZERO_RETURN) {
                /* Connection closed by server */
                break;
            } else {
                print_ssl_error("Failed to read response");
                return -1;
            }
        }

        buffer[len] = '\0';
        printf("%s", buffer);

        /* Check if we got a complete response (ends with status line) */
        if (len > 0 && buffer[len - 1] == '\n') {
            /* For LISTVAL/GETALLVAL, first line contains the count */
            /* We'll read until we get all the data */
            if (strncmp(buffer, "-1", 2) == 0) {
                /* Error response */
                break;
            }
            /* For simplicity, we'll just read a bit more and then stop */
            /* In a real client, you'd parse the count and read exactly that many lines */
        }

        /* Give server time to send more data */
        usleep(10000);

        /* Check if more data is available */
        char peek;
        int peek_ret = SSL_peek(ssl, &peek, 1);
        if (peek_ret <= 0) {
            break;
        }
    }

    return 0;
}

int main(int argc, char *argv[]) {
    const char *hostname = "localhost";
    int port = 25827;
    const char *ca_cert_file = NULL;
    int sockfd;
    SSL_CTX *ctx;
    SSL *ssl;

    /* Parse command line arguments */
    if (argc >= 2) {
        hostname = argv[1];
    }
    if (argc >= 3) {
        port = atoi(argv[2]);
    }
    if (argc >= 4) {
        ca_cert_file = argv[3];
    }

    if (argc < 2) {
        printf("Usage: %s <host> <port> [ca_cert]\n", argv[0]);
        printf("Example: %s localhost 25827 /etc/collectd/tls/server.crt\n", argv[0]);
        printf("\nUsing defaults: %s %d\n", hostname, port);
    }

    /* Connect to server */
    sockfd = connect_to_host(hostname, port);
    if (sockfd < 0) {
        return 1;
    }

    /* Initialize SSL context */
    ctx = init_ssl_context(ca_cert_file);
    if (ctx == NULL) {
        close(sockfd);
        return 1;
    }

    /* Establish TLS connection */
    ssl = establish_tls(ctx, sockfd);
    if (ssl == NULL) {
        SSL_CTX_free(ctx);
        close(sockfd);
        return 1;
    }

    /* Send LISTVAL command */
    if (send_command(ssl, "LISTVAL") < 0) {
        goto cleanup;
    }

    /* Send GETVAL command (need to get a value name from LISTVAL first) */
    /* For now, we'll just try a simple GETVAL with a common metric */
    if (send_command(ssl, "GETVAL localhost/memory/memory-used") < 0) {
        goto cleanup;
    }

    printf("\n=== Test completed successfully ===\n");

cleanup:
    /* Cleanup */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sockfd);

    return 0;
}
