/* Regression checks for libdsm's actual NetBIOS code. No NAS files are used. */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <bdsm/netbios_ns.h>
#include <bdsm/netbios_defs.h>
#include "netbios_utils.h"
#include "netbios_session.h"

static int held[4096];
static int held_count;

static netbios_session *session_pair(int *peer)
{
    int pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    netbios_session *session = netbios_session_new(128);
    assert(session != NULL);
    session->socket = pair[0];
    session->state = NETBIOS_SESSION_CONNECTED;
    *peer = pair[1];
    return session;
}

static void destroy_session(netbios_session *session)
{
    netbios_session_disconnect(session);
    netbios_session_destroy(session);
}

static void *receive_packet(void *opaque)
{
    netbios_session *session = opaque;
    assert(netbios_session_packet_recv(session, NULL) == -1);
    return NULL;
}

static void ignore_entry(void *opaque, netbios_ns_entry *entry)
{
    (void)opaque;
    (void)entry;
}

int main(int argc, char **argv)
{
    alarm(30);
    int minimum = argc > 1 ? atoi(argv[1]) : 1100;
    assert(minimum >= 0 && minimum < 3000);
    while (held_count == 0 || held[held_count - 1] < minimum)
    {
        assert(held_count < (int)(sizeof held / sizeof held[0]));
        held[held_count] = open("/dev/null", O_RDONLY);
        assert(held[held_count] >= 0);
        held_count++;
    }
    printf("Highest held descriptor: %d\n", held[held_count - 1]);
    fflush(stdout);

    struct netbios_abort_ctx abort_ctx;
    assert(netbios_abort_ctx_init(&abort_ctx) == 0);
    assert(!netbios_abort_ctx_is_aborted(&abort_ctx));
    netbios_abort_ctx_abort(&abort_ctx);
    assert(netbios_abort_ctx_is_aborted(&abort_ctx));
    netbios_abort_ctx_destroy(&abort_ctx);
    puts("PASS abort pipe inspection");

    int peer;
    netbios_session *session = session_pair(&peer);
    assert(netbios_wait(&session->abort_ctx, session->socket, true, NULL) == 1);
    struct timeval timeout = {0, 30000};
    assert(netbios_wait(&session->abort_ctx, session->socket, false, &timeout) == 0);
    assert(timeout.tv_sec == 0 && timeout.tv_usec == 0);
    assert(netbios_wait(&session->abort_ctx, session->socket, false, &timeout) == 0);
    errno = 0;
    assert(netbios_wait(&session->abort_ctx, -1, false, NULL) == -1 && errno == EBADF);
    puts("PASS writable socket, finite timeout, and invalid descriptor");

    netbios_session_packet_init(session);
    assert(netbios_session_packet_append(session, "abc", 3) == 1);
    assert(netbios_session_packet_send(session) == 7);
    unsigned char frame[7];
    assert(recv(peer, frame, sizeof frame, MSG_WAITALL) == sizeof frame);
    const unsigned char expected[] = {0, 0, 0, 3, 'a', 'b', 'c'};
    assert(memcmp(frame, expected, sizeof frame) == 0);
    assert(send(peer, expected, sizeof expected, 0) == sizeof expected);
    void *data;
    assert(netbios_session_packet_recv(session, &data) == 3);
    assert(memcmp(data, "abc", 3) == 0);
    close(peer);
    assert(netbios_session_packet_recv(session, NULL) == -1);
    destroy_session(session);
    puts("PASS session send, receive, and peer closure");

    session = session_pair(&peer);
    pthread_t receiver;
    assert(pthread_create(&receiver, NULL, receive_packet, session) == 0);
    usleep(20000);
    netbios_session_abort(session);
    assert(pthread_join(receiver, NULL) == 0);
    close(peer);
    destroy_session(session);
    puts("PASS cancellation wakes a blocked session receive");

    netbios_ns *ns = netbios_ns_new();
    assert(ns != NULL);
    uint32_t ip;
    assert(netbios_ns_resolve(ns, "VLC-FD-TEST", NETBIOS_FILESERVER, &ip) == -1);
    assert(netbios_ns_inverse(ns, htonl(INADDR_LOOPBACK)) == NULL);
    netbios_ns_destroy(ns);
    puts("PASS name resolution and inverse lookup timeout");

    ns = netbios_ns_new();
    assert(ns != NULL);
    netbios_ns_discover_callbacks callbacks = {NULL, ignore_entry, ignore_entry};
    assert(netbios_ns_discover_start(ns, 4, &callbacks) == 0);
    usleep(20000);
    assert(netbios_ns_discover_stop(ns) == 0);
    netbios_ns_destroy(ns);
    puts("PASS cancellation stops network discovery");

    while (held_count > 0)
        close(held[--held_count]);
    puts("All NetBIOS descriptor checks passed");
    return 0;
}
