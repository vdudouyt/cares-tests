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

#define VCLASS_NAME(casename, testname) Virt##casename##_##testname
#define VIRT_NONVIRT_TEST_F(casename, testname)                    \
  class VCLASS_NAME(casename, testname) : public casename {        \
  public:                                                          \
    VCLASS_NAME(casename, testname)()                              \
    {                                                              \
    }                                                              \
    void InnerTestBody();                                          \
  };                                                               \
  GTEST_TEST_(casename, testname, VCLASS_NAME(casename, testname), \
              ::testing::internal::GetTypeId<casename>())          \
  {                                                                \
    InnerTestBody();                                               \
  }                                                                \
  GTEST_TEST_(casename, testname##_virtualized,                    \
              VCLASS_NAME(casename, testname),                     \
              ::testing::internal::GetTypeId<casename>())          \
  {                                                                \
    VirtualizeIO vio(channel_);                                    \
    InnerTestBody();                                               \
  }                                                                \
  void VCLASS_NAME(casename, testname)::InnerTestBody()

/* Assigns virtual IO functions to a channel. These functions simply call
 * the actual system functions.
 */
class VirtualizeIO {
public:
  VirtualizeIO(ares_channel);
  ~VirtualizeIO();

  static const ares_socket_functions default_functions;

private:
  ares_channel_t *channel_;
};

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
   IMPL_SHIM(int, ares_parse_mx_reply, (const unsigned char *abuf, int alen, struct ares_mx_reply **mx_out), (abuf, alen, mx_out))
   IMPL_SHIM(int, ares_parse_naptr_reply, (const unsigned char *abuf, int alen, struct ares_naptr_reply **naptr_out), (abuf, alen, naptr_out))
   IMPL_SHIM(int, ares_parse_ns_reply, (const unsigned char *abuf, int alen, struct hostent **host), (abuf, alen, host))
   IMPL_SHIM(int, ares_parse_ptr_reply, (const unsigned char *abuf, int alen, const void *addr, int addrlen, int family, struct hostent **host), (abuf, alen, addr, addrlen, family, host))
   IMPL_SHIM(int, ares_parse_soa_reply, (const unsigned char *abuf, int alen, struct ares_soa_reply **soa_out), (abuf, alen, soa_out))
   IMPL_SHIM(int, ares_parse_srv_reply, (const unsigned char *abuf, int alen, struct ares_srv_reply **srv_out), (abuf, alen, srv_out))
   IMPL_SHIM(int, ares_parse_txt_reply, (const unsigned char *abuf, int alen, struct ares_txt_reply **txt_out), (abuf, alen, txt_out))
   IMPL_SHIM(int, ares_parse_uri_reply, (const unsigned char *abuf, int alen, struct ares_uri_reply **uri_out), (abuf, alen, uri_out))
   IMPL_SHIM(int, ares_parse_txt_reply_ext, (const unsigned char *abuf, int alen, struct ares_txt_ext **txt_out), (abuf, alen, txt_out))
   IMPL_SHIM(int, ares_set_socket_functions, (const unsigned char *abuf, int alen, struct ares_txt_ext **txt_out), (abuf, alen, txt_out))
};

class DefaultChannelTest : public LibraryTest {
public:
  DefaultChannelTest() : channel_(nullptr)
  {
    /* Enable query cache for live tests */
    struct ares_options opts;
    memset(&opts, 0, sizeof(opts));
    opts.qcache_max_ttl = 300;
    int optmask         = ARES_OPT_QUERY_CACHE;
    EXPECT_EQ(ARES_SUCCESS, ares_init_options(&channel_, &opts, optmask));
    EXPECT_NE(nullptr, channel_);
  }

  ~DefaultChannelTest()
  {
    ares_destroy(channel_);
    channel_ = nullptr;
  }

  // Process all pending work on ares-owned file descriptors.
  void Process(unsigned int cancel_ms = 0);

protected:
  ares_channel_t *channel_;
};

class DefaultChannelModeTest
  : public LibraryTest,
    public ::testing::WithParamInterface<std::string> {
public:
  DefaultChannelModeTest() : channel_(nullptr)
  {
    struct ares_options opts;
    memset(&opts, 0, sizeof(opts));
    opts.lookups = strdup(GetParam().c_str());
    int optmask  = ARES_OPT_LOOKUPS;
    EXPECT_EQ(ARES_SUCCESS, ares_init_options(&channel_, &opts, optmask));
    EXPECT_NE(nullptr, channel_);
    free(opts.lookups);
  }

  ~DefaultChannelModeTest()
  {
    ares_destroy(channel_);
    channel_ = nullptr;
  }

  // Process all pending work on ares-owned file descriptors.
  void Process(unsigned int cancel_ms = 0);

protected:
  ares_channel_t *channel_;
};

// Structure that describes the result of an ares_host_callback invocation.
struct HostResult {
  HostResult() : done_(false), status_(0), timeouts_(0)
  {
  }

  // Whether the callback has been invoked.
  bool    done_;
  // Explicitly provided result information.
  int     status_;
  int     timeouts_;
  // Contents of the hostent structure, if provided.
  HostEnt host_;
};

void          HostCallback(void *data, int status, int timeouts,
                           struct hostent *hostent);
