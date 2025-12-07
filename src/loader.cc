#include <dlfcn.h>
#include <assert.h>
#include <stdexcept>
#include "loader.h"

#define IMPL_SHIM(RET, FUNC, PARAMS, ARGS)                              \
    RET FUNC PARAMS {                                                   \
        RET (*fn) PARAMS = (RET (*) PARAMS) dlsym(impl.handle, #FUNC);  \
        if (!fn) {                                                      \
            throw std::runtime_error("not implemented: " #FUNC);        \
        }                                                               \
        return fn ARGS;                                                 \
    }

ares_impl_t impl;

void load_cares_impl(const char *path) {
   impl.handle = dlopen(path, RTLD_LAZY);
   assert(impl.handle);
}

void unload_cares_impl() {
   dlclose(impl.handle);
}

IMPL_SHIM(void, ares_free_hostent, (struct hostent *host), (host))
IMPL_SHIM(int, ares_parse_a_reply, (const unsigned char *abuf, int alen, struct hostent **host, struct ares_addrttl *addrttls, int *naddrttls), (abuf, alen, host, addrttls, naddrttls))
IMPL_SHIM(int, ares_parse_aaaa_reply, (const unsigned char *abuf, int alen, struct hostent **host, struct ares_addr6ttl *addrttls, int *naddrttls), (abuf, alen, host, addrttls, naddrttls))
IMPL_SHIM(void, ares_free_data, (void *dataptr), (dataptr))
IMPL_SHIM(int, ares_parse_caa_reply, (const unsigned char *abuf, int alen, struct ares_caa_reply **caa_out), (abuf, alen, caa_out))
IMPL_SHIM(int, ares_parse_mx_reply, (const unsigned char *abuf, int alen, struct ares_mx_reply **mx_out), (abuf, alen, mx_out))
IMPL_SHIM(int, ares_parse_naptr_reply, (const unsigned char *abuf, int alen, struct ares_naptr_reply **naptr_out), (abuf, alen, naptr_out))
IMPL_SHIM(int, ares_parse_ns_reply, (const unsigned char *abuf, int alen, struct hostent **host), (abuf, alen, host))
IMPL_SHIM(int, ares_parse_ptr_reply, (const unsigned char *abuf, int alen, const void *addr, int addrlen, int family, struct hostent **host), (abuf, alen, addr, addrlen, family, host))
IMPL_SHIM(int, ares_parse_soa_reply, (const unsigned char *abuf, int alen, struct ares_soa_reply **soa_out), (abuf, alen, soa_out))
IMPL_SHIM(int, ares_parse_srv_reply, (const unsigned char *abuf, int alen, struct ares_srv_reply **srv_out), (abuf, alen, srv_out))
IMPL_SHIM(int, ares_parse_txt_reply, (const unsigned char *abuf, int alen, struct ares_txt_reply **txt_out), (abuf, alen, txt_out))
IMPL_SHIM(int, ares_parse_uri_reply, (const unsigned char *abuf, int alen, struct ares_uri_reply **uri_out), (abuf, alen, uri_out))
IMPL_SHIM(int, ares_parse_txt_reply_ext, (const unsigned char *abuf, int alen, struct ares_txt_ext **txt_out), (abuf, alen, txt_out))

IMPL_SHIM(void, ares_set_socket_functions, (ares_channel_t *channel, const struct ares_socket_functions *funcs, void *user_data), (channel, funcs, user_data));
IMPL_SHIM(void, ares_gethostbyname, (ares_channel_t *channel, const char *name, int family, ares_host_callback callback, void *arg), (channel, name, family, callback, arg));
IMPL_SHIM(int, ares_init_options, (ares_channel_t **channelptr, const struct ares_options *options, int optmask), (channelptr, options, optmask));
IMPL_SHIM(void, ares_destroy, (ares_channel_t *channel), (channel));
IMPL_SHIM(struct timeval *, ares_timeout, (ares_channel_t *channel, struct timeval *maxtv, struct timeval *tv), (channel, maxtv, tv));
IMPL_SHIM(void, ares_cancel, (ares_channel_t *channel), (channel));
IMPL_SHIM(void, ares_process, (ares_channel_t *channel, fd_set *read_fds, fd_set *write_fds), (channel, read_fds, write_fds));
IMPL_SHIM(int, ares_fds, (ares_channel_t *channel, fd_set *read_fds, fd_set *write_fds), (channel, read_fds, write_fds));
IMPL_SHIM(int, ares_gethostbyname_file, (ares_channel_t *channel, const char *name, int family, struct hostent **host), (channel, name, family, host));
IMPL_SHIM(void, ares_gethostbyaddr, (ares_channel_t *channel, const void *addr, int addrlen, int family, ares_host_callback callback, void *arg), (channel, addr, addrlen, family, callback, arg));
IMPL_SHIM(void, ares_search, (ares_channel_t *channel, const char *name, int dnsclass, int type, ares_callback callback, void *arg), (channel, name, dnsclass, type, callback, arg));
IMPL_SHIM(void, ares_getnameinfo, (ares_channel_t *channel, const struct sockaddr *sa, ares_socklen_t salen, int flags, ares_nameinfo_callback callback, void *arg), (channel, sa, salen, flags, callback, arg));
IMPL_SHIM(int, ares_getsock, (ares_channel_t *channel, ares_socket_t *socks, int numsocks), (channel, socks, numsocks));
IMPL_SHIM(int, ares_dup, (ares_channel_t **dest, ares_channel_t *src), (dest, src));
IMPL_SHIM(int, ares_set_servers, (ares_channel_t *channel, const struct ares_addr_node *servers), (channel, servers));
IMPL_SHIM(int, ares_set_servers_ports, (ares_channel_t *channel, const struct ares_addr_port_node *servers), (channel, servers));
IMPL_SHIM(int, ares_set_servers_csv, (ares_channel_t *channel, const char *servers), (channel, servers));
IMPL_SHIM(int, ares_set_servers_ports_csv, (ares_channel_t *channel, const char *servers), (channel, servers));

IMPL_SHIM(void, ares_getaddrinfo, (ares_channel_t *channel, const char *node, const char *service, const struct ares_addrinfo_hints *hints, ares_addrinfo_callback callback, void *arg), (channel, node, service, hints, callback, arg));
IMPL_SHIM(int, ares_inet_pton, (int af, const char *src, void *dst), (af, src, dst));
IMPL_SHIM(void, ares_freeaddrinfo, (struct ares_addrinfo *ai), (ai));
IMPL_SHIM(int, ares_expand_name, (const unsigned char *encoded, const unsigned char *abuf, int alen, char **s, long *enclen), (encoded, abuf, alen, s, enclen));
IMPL_SHIM(void, ares_free_string, (void *str), (str));
