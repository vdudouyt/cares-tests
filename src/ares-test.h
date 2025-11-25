#pragma once
#include <ostream>
#include <vector>
#include <netdb.h>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <ares.h>
#include <cstddef>
#include <netdb.h>
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

class LibraryTest : public ::testing::Test {
public:
   void ares_free_hostent(struct hostent *host) { impl.ares_free_hostent(host); }
   int ares_parse_a_reply(const unsigned char *abuf, int alen, struct hostent **host, struct ares_addrttl *addrttls, int *naddrttls) {
      return impl.ares_parse_a_reply(abuf, alen, host, addrttls, naddrttls);
   }
   int ares_parse_aaaa_reply(const unsigned char *abuf, int alen, struct hostent **host, struct ares_addr6ttl *addrttls, int *naddrttls) {
      return impl.ares_parse_aaaa_reply(abuf, alen, host, addrttls, naddrttls);
   }
};
