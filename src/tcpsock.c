/**
 * collectd - src/tcpsock.c
 * Copyright (C) 2025 Didier Gaudin
 * based on unixsock from Florian octo Forster
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; only version 2 of the License is applicable.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * Authors:
 *   Florian octo Forster <octo at verplant.org>
 *   Didier Gaudin <dgaudin at proginov.com>
 **/

#include "collectd.h"
#include "utils/common/common.h"
#include "utils/cmds/flush.h"
#include "utils/cmds/getthreshold.h"
#include "utils/cmds/getval.h"
#include "utils/cmds/listval.h"
#include "utils/cmds/putnotif.h"
#include "utils/cmds/putval.h"

/* Folks without pthread will need to disable this plugin. */
#include <pthread.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <grp.h>

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

/*
 * Private variables
 */
/* valid configuration file keys */
static const char *config_keys[] = {
    "Listen",
    "TLS",
    "TLSCertificateFile",
    "TLSKeyFile",
    "TLSCAFile",
    "TLSCipherSuite"
};
static int config_keys_num = STATIC_ARRAY_SIZE(config_keys);

/* Configuration */
static char *listen_address = NULL;
static int port = 25827;
static bool use_tls = false;
static char *tls_cert_file = NULL;
static char *tls_key_file = NULL;
static char *tls_ca_file = NULL;
static char *tls_cipher_suite = NULL;

/* Runtime */
static volatile int loop = 0;
static int sock_fd = -1;
static pthread_t listen_thread = (pthread_t)0;

#ifdef HAVE_OPENSSL
static SSL_CTX *ssl_ctx = NULL;
#endif

/*
 * TLS Functions
 */
#ifdef HAVE_OPENSSL
static int tls_init_ctx(void) {
    const SSL_METHOD *method;

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    /* Use TLS 1.2 or higher */
    method = TLS_server_method();
    ssl_ctx = SSL_CTX_new(method);

    if (ssl_ctx == NULL) {
        ERROR("tcpsock plugin: Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /* Set minimum TLS version to 1.2 */
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);

    /* Configure cipher suite if provided */
    if (tls_cipher_suite != NULL) {
        if (SSL_CTX_set_cipher_list(ssl_ctx, tls_cipher_suite) != 1) {
            ERROR("tcpsock plugin: Failed to set cipher suite: %s", tls_cipher_suite);
            ERR_print_errors_fp(stderr);
            return -1;
        }
    } else {
        /* Use secure default ciphers */
        SSL_CTX_set_cipher_list(ssl_ctx, "HIGH:!aNULL:!MD5:!RC4");
    }

    /* Load server certificate */
    if (tls_cert_file == NULL) {
        ERROR("tcpsock plugin: TLS enabled but TLSCertificateFile not specified");
        return -1;
    }

    if (SSL_CTX_use_certificate_file(ssl_ctx, tls_cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERROR("tcpsock plugin: Failed to load certificate file: %s", tls_cert_file);
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /* Load server private key */
    if (tls_key_file == NULL) {
        ERROR("tcpsock plugin: TLS enabled but TLSKeyFile not specified");
        return -1;
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, tls_key_file, SSL_FILETYPE_PEM) <= 0) {
        ERROR("tcpsock plugin: Failed to load private key file: %s", tls_key_file);
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /* Verify that private key matches certificate */
    if (!SSL_CTX_check_private_key(ssl_ctx)) {
        ERROR("tcpsock plugin: Private key does not match certificate");
        return -1;
    }

    /* Load CA certificate for client verification (optional) */
    if (tls_ca_file != NULL) {
        if (SSL_CTX_load_verify_locations(ssl_ctx, tls_ca_file, NULL) != 1) {
            ERROR("tcpsock plugin: Failed to load CA certificate: %s", tls_ca_file);
            ERR_print_errors_fp(stderr);
            return -1;
        }

        /* Require client certificate verification */
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        SSL_CTX_set_verify_depth(ssl_ctx, 4);

        INFO("tcpsock plugin: Client certificate verification enabled with CA: %s", tls_ca_file);
    } else {
        /* No client verification required */
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
        INFO("tcpsock plugin: Client certificate verification disabled");
    }

    INFO("tcpsock plugin: TLS context initialized successfully");
    INFO("tcpsock plugin:   Certificate: %s", tls_cert_file);
    INFO("tcpsock plugin:   Private Key: %s", tls_key_file);

    return 0;
}

static void tls_cleanup(void) {
    if (ssl_ctx != NULL) {
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = NULL;
    }
    EVP_cleanup();
}
#endif /* HAVE_OPENSSL */

/*
 * Socket Functions
 */
static int us_open_socket(void) {
    struct sockaddr_in sa;
    int status;
    int optval = 1;

    sock_fd = socket(PF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        char errbuf[1024];
        ERROR("tcpsock plugin: socket failed: %s", sstrerror(errno, errbuf, sizeof(errbuf)));
        return -1;
    }

    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int));

    memset((char *)&sa, 0, sizeof(struct sockaddr_in));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);

    /* Parse listen address */
    if (listen_address != NULL) {
        if (inet_pton(AF_INET, listen_address, &sa.sin_addr) != 1) {
            ERROR("tcpsock plugin: Invalid listen address: %s", listen_address);
            close(sock_fd);
            sock_fd = -1;
            return -1;
        }
    } else {
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    status = bind(sock_fd, (struct sockaddr *)&sa, sizeof(sa));
    if (status != 0) {
        char errbuf[1024];
        sstrerror(errno, errbuf, sizeof(errbuf));
        ERROR("tcpsock plugin: bind failed: %s", errbuf);
        close(sock_fd);
        sock_fd = -1;
        return -1;
    }

    status = listen(sock_fd, 8);
    if (status != 0) {
        char errbuf[1024];
        ERROR("tcpsock plugin: listen failed: %s", sstrerror(errno, errbuf, sizeof(errbuf)));
        close(sock_fd);
        sock_fd = -1;
        return -1;
    }

    INFO("tcpsock plugin: Listening on %s:%d (TLS: %s)",
         listen_address ? listen_address : "0.0.0.0",
         port,
         use_tls ? "enabled" : "disabled");

    return 0;
}

/*
 * Client Handler
 */
typedef struct {
    int fd;
#ifdef HAVE_OPENSSL
    SSL *ssl;
#endif
    bool is_tls;
} client_context_t;

static int client_read_line(client_context_t *ctx, FILE *fhin, char *buffer, size_t buffer_size) {
#ifdef HAVE_OPENSSL
    if (ctx->is_tls && ctx->ssl != NULL) {
        /* TLS read */
        int bytes_read = 0;
        while (bytes_read < (int)buffer_size - 1) {
            int ret = SSL_read(ctx->ssl, buffer + bytes_read, 1);
            if (ret <= 0) {
                int ssl_err = SSL_get_error(ctx->ssl, ret);
                if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
                    continue;
                }
                return -1;
            }
            if (buffer[bytes_read] == '\n') {
                buffer[bytes_read] = '\0';
                return bytes_read;
            }
            bytes_read++;
        }
        buffer[bytes_read] = '\0';
        return bytes_read;
    } else
#endif
    {
        /* Plain TCP read - use provided FILE* */
        if (fhin == NULL) {
            return -1;
        }
        if (fgets(buffer, buffer_size, fhin) == NULL) {
            return -1;
        }
        return strlen(buffer);
    }
}

static int client_write(client_context_t *ctx, const char *data, size_t len) {
#ifdef HAVE_OPENSSL
    if (ctx->is_tls && ctx->ssl != NULL) {
        /* TLS write */
        int ret = SSL_write(ctx->ssl, data, len);
        if (ret <= 0) {
            int ssl_err = SSL_get_error(ctx->ssl, ret);
            ERROR("tcpsock plugin: SSL_write failed: %d", ssl_err);
            return -1;
        }
        return ret;
    } else
#endif
    {
        /* Plain TCP write */
        return write(ctx->fd, data, len);
    }
}

static void *us_handle_client(void *arg) {
    client_context_t *ctx = (client_context_t *)arg;
    FILE *fhin = NULL;
    FILE *fhout = NULL;

    DEBUG("tcpsock plugin: us_handle_client: Reading from fd #%i (TLS: %s)",
          ctx->fd, ctx->is_tls ? "yes" : "no");

#ifdef HAVE_OPENSSL
    /* Perform TLS handshake if TLS is enabled */
    if (ctx->is_tls) {
        ctx->ssl = SSL_new(ssl_ctx);
        if (ctx->ssl == NULL) {
            ERROR("tcpsock plugin: SSL_new failed");
            ERR_print_errors_fp(stderr);
            close(ctx->fd);
            free(ctx);
            pthread_exit((void *)1);
        }

        SSL_set_fd(ctx->ssl, ctx->fd);

        int ret = SSL_accept(ctx->ssl);
        if (ret <= 0) {
            int ssl_err = SSL_get_error(ctx->ssl, ret);
            ERROR("tcpsock plugin: SSL_accept failed: %d", ssl_err);
            ERR_print_errors_fp(stderr);
            SSL_free(ctx->ssl);
            close(ctx->fd);
            free(ctx);
            pthread_exit((void *)1);
        }

        INFO("tcpsock plugin: TLS handshake completed successfully");
    }
#endif

    /* Create input/output buffers for plain TCP (for TLS we use client_read/write) */
    if (!ctx->is_tls) {
        /* Input stream */
        fhin = fdopen(ctx->fd, "r");
        if (fhin == NULL) {
            char errbuf[1024];
            ERROR("tcpsock plugin: fdopen input failed: %s", sstrerror(errno, errbuf, sizeof(errbuf)));
            close(ctx->fd);
            free(ctx);
            pthread_exit((void *)1);
        }

        /* Output stream */
        int fdout = dup(ctx->fd);
        if (fdout < 0) {
            char errbuf[1024];
            ERROR("tcpsock plugin: dup failed: %s", sstrerror(errno, errbuf, sizeof(errbuf)));
            fclose(fhin);
            close(ctx->fd);
            free(ctx);
            pthread_exit((void *)1);
        }

        fhout = fdopen(fdout, "w");
        if (fhout == NULL) {
            char errbuf[1024];
            ERROR("tcpsock plugin: fdopen output failed: %s", sstrerror(errno, errbuf, sizeof(errbuf)));
            fclose(fhin);
            close(ctx->fd);
            close(fdout);
            free(ctx);
            pthread_exit((void *)1);
        }

        /* change output buffer to line buffered mode */
        if (setvbuf(fhout, NULL, _IOLBF, 0) != 0) {
            char errbuf[1024];
            ERROR("tcpsock plugin: setvbuf failed: %s", sstrerror(errno, errbuf, sizeof(errbuf)));
            fclose(fhin);
            fclose(fhout);
            close(ctx->fd);
            free(ctx);
            pthread_exit((void *)1);
        }
    }

    /* Main command processing loop */
    while (42) {
        char buffer[1024];
        char buffer_copy[1024];
        char *fields[128];
        int fields_num;
        int len;

        /* Read command */
        errno = 0;
        len = client_read_line(ctx, fhin, buffer, sizeof(buffer));
        if (len < 0) {
            if (errno != 0) {
                char errbuf[1024];
                WARNING("tcpsock plugin: failed to read from socket #%i: %s",
                        ctx->fd, sstrerror(errno, errbuf, sizeof(errbuf)));
            }
            break;
        }

        /* Strip newlines and carriage returns */
        while ((len > 0) && ((buffer[len - 1] == '\n') || (buffer[len - 1] == '\r')))
            buffer[--len] = '\0';

        if (len == 0)
            continue;

        sstrncpy(buffer_copy, buffer, sizeof(buffer_copy));

        fields_num = strsplit(buffer_copy, fields, sizeof(fields) / sizeof(fields[0]));
        if (fields_num < 1) {
            const char *err_msg = "-1 Internal error\n";
            if (ctx->is_tls) {
                client_write(ctx, err_msg, strlen(err_msg));
            } else {
                fprintf(fhout, "%s", err_msg);
            }
            break;
        }

        /* Process command - TLS and plain TCP use same handlers */
        FILE *cmd_output = fhout;
        char *mem_buffer = NULL;
        size_t mem_size = 0;

        /* For TLS, capture output in memory stream */
        if (ctx->is_tls) {
            cmd_output = open_memstream(&mem_buffer, &mem_size);
            if (cmd_output == NULL) {
                const char *err_msg = "-1 Internal error: open_memstream failed\n";
                client_write(ctx, err_msg, strlen(err_msg));
                continue;
            }
        }

        /* Execute command handler (writes to cmd_output) */
        if (strcasecmp(fields[0], "getval") == 0) {
            cmd_handle_getval(cmd_output, buffer);
        } else if (strcasecmp(fields[0], "getthreshold") == 0) {
            handle_getthreshold(cmd_output, buffer);
        } else if (strcasecmp(fields[0], "putval") == 0) {
            cmd_handle_putval(cmd_output, buffer);
        } else if (strcasecmp(fields[0], "listval") == 0) {
            cmd_handle_listval(cmd_output, buffer);
        } else if (strcasecmp(fields[0], "getallval") == 0) {
            cmd_handle_getallval(cmd_output, buffer);
        } else if (strcasecmp(fields[0], "putnotif") == 0) {
            handle_putnotif(cmd_output, buffer);
        } else if (strcasecmp(fields[0], "flush") == 0) {
            cmd_handle_flush(cmd_output, buffer);
        } else {
            if (fprintf(cmd_output, "-1 Unknown command: %s\n", fields[0]) < 0) {
                WARNING("tcpsock plugin: failed to write response: %s", STRERRNO);
                if (ctx->is_tls && cmd_output != NULL) {
                    fclose(cmd_output);
                    free(mem_buffer);
                }
                break;
            }
        }

        /* For TLS, flush memstream and send via SSL */
        if (ctx->is_tls) {
            fflush(cmd_output);
            fclose(cmd_output);

            if (mem_buffer != NULL && mem_size > 0) {
                client_write(ctx, mem_buffer, mem_size);
            }

            free(mem_buffer);
            mem_buffer = NULL;
        }
    }

    DEBUG("tcpsock plugin: us_handle_client: Exiting..");

#ifdef HAVE_OPENSSL
    if (ctx->ssl != NULL) {
        SSL_shutdown(ctx->ssl);
        SSL_free(ctx->ssl);
    }
#endif

    if (fhin != NULL) {
        fclose(fhin);
    }

    if (fhout != NULL) {
        fclose(fhout);
    }

    close(ctx->fd);
    free(ctx);

    pthread_exit((void *)0);
    return ((void *)0);
}

static void *us_server_thread(void __attribute__((unused)) * arg) {
    int status;
    pthread_t th;
    pthread_attr_t th_attr;

    if (us_open_socket() != 0)
        pthread_exit((void *)1);

    while (loop != 0) {
        DEBUG("tcpsock plugin: Calling accept..");
        status = accept(sock_fd, NULL, NULL);
        if (status < 0) {
            char errbuf[1024];

            if (errno == EINTR)
                continue;

            /* Si shutdown en cours (loop=0), sock_fd déjà fermé par us_shutdown() */
            if (loop == 0) {
                INFO("tcpsock plugin: accept() interrupted by shutdown");
                pthread_exit((void *)0);
            }

            ERROR("tcpsock plugin: accept failed: %s",
                  sstrerror(errno, errbuf, sizeof(errbuf)));
            close(sock_fd);
            sock_fd = -1;
            pthread_exit((void *)1);
        }

        client_context_t *ctx = (client_context_t *)malloc(sizeof(client_context_t));
        if (ctx == NULL) {
            char errbuf[1024];
            WARNING("tcpsock plugin: malloc failed: %s",
                    sstrerror(errno, errbuf, sizeof(errbuf)));
            close(status);
            continue;
        }

        ctx->fd = status;
        ctx->is_tls = use_tls;
#ifdef HAVE_OPENSSL
        ctx->ssl = NULL;
#endif

        DEBUG("Spawning child to handle connection on fd #%i", ctx->fd);

        pthread_attr_init(&th_attr);
        pthread_attr_setdetachstate(&th_attr, PTHREAD_CREATE_DETACHED);

        status = pthread_create(&th, &th_attr, us_handle_client, (void *)ctx);
        if (status != 0) {
            char errbuf[1024];
            WARNING("tcpsock plugin: pthread_create failed: %s",
                    sstrerror(errno, errbuf, sizeof(errbuf)));
            close(ctx->fd);
            free(ctx);
            continue;
        }
    }

    close(sock_fd);
    sock_fd = -1;

    return ((void *)0);
}

static int us_config(const char *key, const char *val) {
    if (strcasecmp(key, "Listen") == 0) {
        /* Parse "address" "port" format */
        char *addr_copy = strdup(val);
        char *space = strchr(addr_copy, ' ');

        if (space != NULL) {
            *space = '\0';
            char *port_str = space + 1;

            /* Remove quotes */
            if (addr_copy[0] == '"')
                addr_copy++;
            char *end = strchr(addr_copy, '"');
            if (end != NULL)
                *end = '\0';

            if (port_str[0] == '"')
                port_str++;
            end = strchr(port_str, '"');
            if (end != NULL)
                *end = '\0';

            listen_address = strdup(addr_copy);

            char *endptr = NULL;
            long new_port;
            errno = 0;
            new_port = strtol(port_str, &endptr, 10);

            if ((errno != 0) || (port_str == endptr) || (*endptr != '\0')) {
                ERROR("tcpsock plugin: Invalid port number: %s", port_str);
                free(addr_copy);
                return 1;
            }

            if (new_port <= 0 || new_port >= 65536) {
                ERROR("tcpsock plugin: Invalid port number (out of range): %ld", new_port);
                free(addr_copy);
                return 1;
            }

            port = (int)new_port;
        }

        free(addr_copy);
    } else if (strcasecmp(key, "TLS") == 0) {
        if (IS_TRUE(val)) {
            use_tls = true;
#ifndef HAVE_OPENSSL
            WARNING("tcpsock plugin: TLS requested but OpenSSL support not compiled in");
            return 1;
#endif
        } else {
            use_tls = false;
        }
    } else if (strcasecmp(key, "TLSCertificateFile") == 0) {
        sfree(tls_cert_file);
        tls_cert_file = strdup(val);
    } else if (strcasecmp(key, "TLSKeyFile") == 0) {
        sfree(tls_key_file);
        tls_key_file = strdup(val);
    } else if (strcasecmp(key, "TLSCAFile") == 0) {
        sfree(tls_ca_file);
        tls_ca_file = strdup(val);
    } else if (strcasecmp(key, "TLSCipherSuite") == 0) {
        sfree(tls_cipher_suite);
        tls_cipher_suite = strdup(val);
    } else {
        return -1;
    }

    return 0;
}

static int us_init(void) {
    static int have_init = 0;
    int status;

    /* Initialize only once. */
    if (have_init != 0)
        return 0;
    have_init = 1;

#ifdef HAVE_OPENSSL
    /* Initialize TLS if enabled */
    if (use_tls) {
        if (tls_init_ctx() != 0) {
            ERROR("tcpsock plugin: TLS initialization failed");
            return -1;
        }
    }
#endif

    loop = 1;

    status = pthread_create(&listen_thread, NULL, us_server_thread, NULL);
    if (status != 0) {
        char errbuf[1024];
        ERROR("tcpsock plugin: pthread_create failed: %s",
              sstrerror(errno, errbuf, sizeof(errbuf)));
        return -1;
    }

    return 0;
}

static int us_shutdown(void) {
    void *ret;

    INFO("tcpsock plugin: Shutting down...");

    loop = 0;

    if (listen_thread != (pthread_t)0) {
        /* Close the listening socket to unblock accept() */
        if (sock_fd >= 0) {
            INFO("tcpsock plugin: Closing listening socket to unblock accept()");
            close(sock_fd);
            sock_fd = -1;
        }

        /* Send signal to unblock thread (same as unixsock) */
        INFO("tcpsock plugin: Sending SIGTERM to listen thread...");
        pthread_kill(listen_thread, SIGTERM);

        INFO("tcpsock plugin: Waiting for listen thread to terminate...");
        pthread_join(listen_thread, &ret);
        listen_thread = (pthread_t)0;
        INFO("tcpsock plugin: Listen thread terminated");
    }

#ifdef HAVE_OPENSSL
    tls_cleanup();
#endif

    sfree(listen_address);
    sfree(tls_cert_file);
    sfree(tls_key_file);
    sfree(tls_ca_file);
    sfree(tls_cipher_suite);

    plugin_unregister_config("tcpsock");
    plugin_unregister_init("tcpsock");
    plugin_unregister_shutdown("tcpsock");

    return 0;
}

void module_register(void) {
    plugin_register_config("tcpsock", us_config, config_keys, config_keys_num);
    plugin_register_init("tcpsock", us_init);
    plugin_register_shutdown("tcpsock", us_shutdown);
}

/* vim: set sw=4 ts=4 sts=4 tw=78 : */
