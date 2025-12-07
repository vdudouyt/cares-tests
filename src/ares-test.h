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
#include "ares_dns.h"

extern std::vector<int> families;
extern std::vector<std::pair<int, bool>> families_modes;

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

#include "loader.h"

class LibraryTest : public ::testing::Test {
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

/* search tests */
struct SearchResult {
  // Whether the callback has been invoked.
  bool              done_;
  // Explicitly provided result information.
  int               status_;
  int               timeouts_;
  std::vector<byte> data_;
};

void SearchCallback(void *data, int status, int timeouts, unsigned char *abuf,
                    int alen);

struct NameInfoResult {
  // Whether the callback has been invoked.
  bool        done_;
  // Explicitly provided result information.
  int         status_;
  int         timeouts_;
  std::string node_;
  std::string service_;
};

void NameInfoCallback(void *data, int status, int timeouts, char *node,
                      char *service);

std::set<ares_socket_t> NoExtraFDs();

void ProcessWork(ares_channel_t *channel,
   std::function<std::set<ares_socket_t>()> get_extrafds,
   std::function<void(ares_socket_t)> process_extra,
   unsigned int cancel_ms = 0);

class MockServer {
public:
  MockServer(int family, unsigned short port);
  ~MockServer();

  // Mock method indicating the processing of a particular <name, RRtype>
  // request.
  MOCK_METHOD2(OnRequest, void(const std::string &name, int rrtype));

  // Set the reply to be sent next; the query ID field will be overwritten
  // with the value from the request.
  void SetReplyData(const std::vector<byte> &reply)
  {
    reply_ = reply;
  }

  void SetReply(const DNSPacket *reply)
  {
    SetReplyData(reply->data());
  }

  void SetReplyQID(int qid)
  {
    qid_ = qid;
  }

  void Disconnect()
  {
    for (ares_socket_t fd : connfds_) {
      close(fd);
    }
    connfds_.clear();
    free(tcp_data_);
    tcp_data_     = NULL;
    tcp_data_len_ = 0;
  }

  // The set of file descriptors that the server handles.
  std::set<ares_socket_t> fds() const;

  // Process activity on a file descriptor.
  void                    ProcessFD(ares_socket_t fd);

  // Ports the server is responding to
  unsigned short          udpport() const
  {
    return udpport_;
  }

  unsigned short tcpport() const
  {
    return tcpport_;
  }

private:
  void           ProcessRequest(ares_socket_t fd, struct sockaddr_storage *addr,
                                ares_socklen_t addrlen, int qid, const std::string &name,
                                int rrtype);
  void           ProcessPacket(ares_socket_t fd, struct sockaddr_storage *addr,
                               ares_socklen_t addrlen, byte *data, int len);
  unsigned short udpport_;
  unsigned short tcpport_;
  ares_socket_t  udpfd_;
  ares_socket_t  tcpfd_;
  std::set<ares_socket_t> connfds_;
  std::vector<byte>       reply_;
  int                     qid_;
  unsigned char          *tcp_data_;
  size_t                  tcp_data_len_;
};

class MockChannelOptsTest : public LibraryTest {
public:
  MockChannelOptsTest(int count, int family, bool force_tcp,
                      struct ares_options *givenopts, int optmask);
  ~MockChannelOptsTest();

  // Process all pending work on ares-owned and mock-server-owned file
  // descriptors.
  void Process(unsigned int cancel_ms = 0);

protected:
  // NiceMockServer doesn't complain about uninteresting calls.
  typedef testing::NiceMock<MockServer>                NiceMockServer;
  typedef std::vector<std::unique_ptr<NiceMockServer>> NiceMockServers;

  std::set<ares_socket_t>                              fds() const;
  void                   ProcessFD(ares_socket_t fd);

  static NiceMockServers BuildServers(int count, int family,
                                      unsigned short base_port);

  NiceMockServers        servers_;
  // Convenience reference to first server.
  NiceMockServer        &server_;
  ares_channel_t        *channel_;
};

struct AddrInfoDeleter {                                                                                                                   
  void operator()(ares_addrinfo *ptr)
  {
    if (ptr) {
      ares_freeaddrinfo(ptr);
    }
  }
};

// C++ wrapper for struct ares_addrinfo.
using AddrInfo = std::unique_ptr<ares_addrinfo, AddrInfoDeleter>;                                                                          

std::ostream &operator<<(std::ostream &os, const AddrInfo &result);

struct AddrInfoResult {
  AddrInfoResult() : done_(false), status_(-1), timeouts_(0)
  {
  }

  // Whether the callback has been invoked.
  bool     done_;
  // Explicitly provided result information.
  int      status_;
  int      timeouts_;
  // Contents of the ares_addrinfo structure, if provided.
  AddrInfo ai_;
};

std::ostream &operator<<(std::ostream &os, const AddrInfoResult &result);

void AddrInfoCallback(void *data, int status, int timeouts,
                      struct ares_addrinfo *res);

// gMock action to set the reply for a mock server.
ACTION_P2(SetReplyData, mockserver, data)
{
  mockserver->SetReplyData(data);
}

ACTION_P2(SetReply, mockserver, reply)
{
  mockserver->SetReply(reply);
}
