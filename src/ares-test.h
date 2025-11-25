#pragma once
#include <ostream>
#include <vector>
#include <netdb.h>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <ares.h>
#include <cstddef>
#include <netdb.h>
#include <dlfcn.h>
#include "dns-proto.h"

struct HostEnt {
  HostEnt() : addrtype_(-1)
  {
  }

  HostEnt(const struct hostent *hostent);
  std::string              name_;
  std::vector<std::string> aliases_;
  int                      addrtype_;  // AF_INET or AF_INET6
  std::vector<std::string> addrs_;
};

std::ostream &operator<<(std::ostream &os, const HostEnt &result);

extern "C" {
#include "impl.h"
}

#define IMPL_SHIM(RET, FUNC, PARAMS, ARGS)                              \
    RET FUNC PARAMS {                                                   \
        RET (*fn) PARAMS = (RET (*) PARAMS) dlsym(impl.handle, #FUNC);  \
        if (!fn) {                                                      \
            throw std::runtime_error("not implemented: " #FUNC);        \
        }                                                               \
        return fn ARGS;                                                 \
    }

class LibraryTest : public ::testing::Test {
public:
   IMPL_SHIM(void, ares_free_hostent, (struct hostent *host), (host))
   IMPL_SHIM(int, ares_parse_a_reply, (const unsigned char *abuf, int alen, struct hostent **host, struct ares_addrttl *addrttls, int *naddrttls), (abuf, alen, host, addrttls, naddrttls))
   IMPL_SHIM(int, ares_parse_aaaa_reply, (const unsigned char *abuf, int alen, struct hostent **host, struct ares_addr6ttl *addrttls, int *naddrttls), (abuf, alen, host, addrttls, naddrttls))
   IMPL_SHIM(void, ares_free_data, (void *dataptr), (dataptr))
   IMPL_SHIM(int, ares_parse_caa_reply, (const unsigned char *abuf, int alen, struct ares_caa_reply **caa_out), (abuf, alen, caa_out))
   IMPL_SHIM(int, ares_parse_mx_reply, (const unsigned char *abuf, int alen, struct ares_mx_reply **mx_out), (abuf, alen, mx_out));
};
