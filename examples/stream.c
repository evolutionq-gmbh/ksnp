/*
A simple KSNP client that simply prints hex-encoded key data to stdout. It opens
an arbitrary stream to a given SAE.

This is an example program and hence performs little to no error checking. This
is by no means ready for production use.
*/

#include <netdb.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include "ksnp/types.h"
#include <ksnp/client.h>
#include <ksnp/serde.h>

#define KEY_SIZE 32
#define BUFFER_SIZE 4096

struct ksnp_client_event next_event(struct ksnp_client *client, int sock);
void                     run_client(int sock, char const *sae);

// Keep performing IO until some event is generated or the server closes the
// connection.
struct ksnp_client_event next_event(struct ksnp_client *client, int sock)
{
    unsigned char buf[BUFFER_SIZE];

    while (true) {
        // Flush the write buffer before attempting to read, as the server may
        // need more information before it continues.
        while (ksnp_client_want_write(client)) {
            size_t buf_len = BUFFER_SIZE;
            ksnp_client_write_data(client, buf, &buf_len);
            write(sock, buf, buf_len);
        }

        // Read data until a complete message has arrived or EOF occurs.
        while (ksnp_client_want_read(client)) {
            size_t  buf_len = BUFFER_SIZE;
            ssize_t count   = read(sock, buf, buf_len);
            if (count == 0) {
                ksnp_client_close_connection(client, KSNP_CLOSE_READ);
            } else {
                buf_len = (size_t)count;
                ksnp_client_read_data(client, buf, &buf_len);
            }
        }

        struct ksnp_client_event event;
        ksnp_client_next_event(client, &event);
        // Check for the next event. If none, check if more IO is required. If
        // not, the client can stop polling for further events.
        if (event.type == KSNP_CLIENT_EVENT_NONE) {
            if (!ksnp_client_want_read(client) && !ksnp_client_want_write(client)) {
                return event;
            }
        } else {
            return event;
        }
    }
}

void run_client(int sock, char const *sae)
{
    // Use the default message context, with buffers that always accept more
    // data.
    struct ksnp_message_context *ctx;
    ksnp_message_context_create(&ctx);

    struct ksnp_client *client;
    ksnp_client_create(&client, ctx);

    struct ksnp_stream_open_params stream_params = {
        .destination = {.sae = sae},
        .capacity    = KEY_SIZE,
    };
    ksnp_client_open_stream(client, &stream_params);

    bool run        = true;
    bool need_close = true;
    while (run) {
        struct ksnp_client_event event = next_event(client, sock);
        switch (event.type) {
        case KSNP_CLIENT_EVENT_STREAM_OPEN:
            if (event.stream_open.code != 0) {
                (void)fputs("Failed to open a stream\n", stderr);
                run = false;
            } else {
                char stream_str[UUID_STR_LEN];
                uuid_unparse(event.stream_open.parameters.reply->stream_id, stream_str);
                (void)fprintf(stderr, "Opened stream %s\n", stream_str);
            }
            break;
        case KSNP_CLIENT_EVENT_STREAM_KEY_DATA:
            for (size_t i = 0; i < event.key_data.key_data.len; i++) {
                if (printf("%02x", (unsigned int)event.key_data.key_data.data[i]) == -1) {
                    exit(EXIT_FAILURE);
                }
            }
            ksnp_client_add_capacity(client, KEY_SIZE);
            break;
        case KSNP_CLIENT_EVENT_NONE:  // No event means server closed the connection
            need_close = false;
            // fallthrough
            __attribute__((fallthrough));
        case KSNP_CLIENT_EVENT_STREAM_SUSPEND:
        case KSNP_CLIENT_EVENT_STREAM_CLOSE:
            run = false;
            break;
        case KSNP_CLIENT_EVENT_ERROR:
            (void)fprintf(stderr, "Protocol error %u\n", event.error.code);
            if (event.error.description != NULL) {
                (void)fprintf(stderr, "  %s\n", event.error.description);
            }
            run = false;
            break;
        case KSNP_CLIENT_EVENT_HANDSHAKE:
        case KSNP_CLIENT_EVENT_KEEP_ALIVE:
            // Ignore
            break;
        default:
            (void)fprintf(stderr, "Unknown event %d\n", +event.type);
        }
    }

    ksnp_client_close_connection(client, KSNP_CLOSE_WRITE);

    if (need_close) {
        // Wait for the server to close the connection
        while (next_event(client, sock).type != KSNP_CLIENT_EVENT_NONE) {
            // Flushing write data, completing all IO
        }
    }

    shutdown(sock, SHUT_WR);
}

int main(int argc, char const *argv[])
{
    if (argc != 4) {
        (void)fprintf(stderr, "Usage: %s host port SAE\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    struct addrinfo  hints  = {.ai_family = AF_INET6, .ai_socktype = SOCK_STREAM};
    struct addrinfo *result = NULL;

    int gai_res = getaddrinfo(argv[1], argv[2], &hints, &result);
    if (gai_res != 0) {
        (void)fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai_res));
        exit(EXIT_FAILURE);
    }

    int sock = -1;
    for (struct addrinfo *rp = result; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == -1) {
            continue;
        }

        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }

        close(sock);
    }
    freeaddrinfo(result);
    if (sock == -1) {
        (void)fprintf(stderr, "Unable to connect to %s %s\n", argv[1], argv[2]);
        exit(EXIT_FAILURE);
    }

    run_client(sock, argv[3]);

    close(sock);
}
