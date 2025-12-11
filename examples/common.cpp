#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

#include "common.hpp"

using namespace ksnp;

auto connect(char const *host, char const *port_spec) -> fd
{
    addrinfo hints = {.ai_flags     = AI_NUMERICSERV,
                      .ai_family    = AF_UNSPEC,
                      .ai_socktype  = SOCK_STREAM,
                      .ai_protocol  = IPPROTO_TCP,
                      .ai_addrlen   = 0,
                      .ai_addr      = nullptr,
                      .ai_canonname = nullptr,
                      .ai_next      = nullptr};

    addrinfo *addr_res;
    if (auto gai_err = getaddrinfo(host, port_spec, &hints, &addr_res); gai_err != 0) {
        throw gai_exception(gai_err, "Failed to resolve address");
    }
    unique_obj<addrinfo *, freeaddrinfo, nullptr> addr_info(addr_res);

    for (auto *rp = addr_info.get(); rp != nullptr; rp = rp->ai_next) {
        fd sfd(socket(rp->ai_family, rp->ai_socktype | SOCK_CLOEXEC, rp->ai_protocol));
        if (!sfd) {
            continue;
        }

        if (connect(*sfd, rp->ai_addr, rp->ai_addrlen) != -1) {
            return sfd;
        }
    }

    throw errno_exception(errno, "Failed to connect");
}

auto listen(char const *addr, char const *port_spec, int queue_size) -> fd
{
    addrinfo hints = {.ai_flags     = AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV,
                      .ai_family    = AF_UNSPEC,
                      .ai_socktype  = SOCK_STREAM,
                      .ai_protocol  = IPPROTO_TCP,
                      .ai_addrlen   = 0,
                      .ai_addr      = nullptr,
                      .ai_canonname = nullptr,
                      .ai_next      = nullptr};

    addrinfo *addr_res;
    if (auto gai_err = getaddrinfo(addr, port_spec, &hints, &addr_res); gai_err != 0) {
        throw gai_exception(gai_err, "Failed to resolve address");
    }
    unique_obj<addrinfo *, freeaddrinfo, nullptr> addr_info(addr_res);

    for (auto *rp = addr_info.get(); rp != nullptr; rp = rp->ai_next) {
        fd sfd(socket(rp->ai_family, rp->ai_socktype | SOCK_CLOEXEC, rp->ai_protocol));
        if (!sfd) {
            continue;
        }

        int reuse_addr = 1;
        (void)setsockopt(*sfd, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr));

        if (bind(*sfd, rp->ai_addr, rp->ai_addrlen) != -1) {
            check_errno(listen(*sfd, queue_size), "Failed to listen");
            return sfd;
        }
    }

    throw errno_exception(errno, "Failed to bind");
}
