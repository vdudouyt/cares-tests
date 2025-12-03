/* MIT License
 *
 * Copyright (c) The c-ares project and its contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 */
// This file includes tests that attempt to do real lookups
// of DNS names using the local machine's live infrastructure.
// As a result, we don't check the results very closely, to allow
// for varying local configurations.

#include "ares-test.h"

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

// Use the address of CloudFlare's public DNS servers as example addresses that are
// likely to be accessible everywhere/everywhen.  We used to use google but they
// stopped returning reverse dns answers in Dec 2023
unsigned char cflare_addr4[4]  = { 0x01, 0x01, 0x01, 0x01 };
unsigned char cflare_addr6[16] = {
  0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11
};

MATCHER_P(IncludesAtLeastNumAddresses, n, "") {
  if(!arg)
    return false;
  int cnt = 0;
  for (const ares_addrinfo_node* ai = arg->nodes; ai != NULL; ai = ai->ai_next)
    cnt++;
  return cnt >= n;
}

MATCHER_P(OnlyIncludesAddrType, addrtype, "") {
  if(!arg)
    return false;
  for (const ares_addrinfo_node* ai = arg->nodes; ai != NULL; ai = ai->ai_next)
    if (ai->ai_family != addrtype)
      return false;
  return true;
}

MATCHER_P(IncludesAddrType, addrtype, "") {
  if(!arg)
    return false;
  for (const ares_addrinfo_node* ai = arg->nodes; ai != NULL; ai = ai->ai_next)
    if (ai->ai_family == addrtype)
      return true;
  return false;
}

//VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetAddrInfoV4) {
  //struct ares_addrinfo_hints hints = {};
  //hints.ai_family = AF_INET;
  //AddrInfoResult result;
  //ares_getaddrinfo(channel_, "www.google.com.", NULL, &hints, AddrInfoCallback, &result);
  //Process();
  //EXPECT_TRUE(result.done_);
  //EXPECT_EQ(ARES_SUCCESS, result.status_);
  //EXPECT_THAT(result.ai_, IncludesAtLeastNumAddresses(1));
  //EXPECT_THAT(result.ai_, OnlyIncludesAddrType(AF_INET));
//}

//VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetAddrInfoV6) {
  //struct ares_addrinfo_hints hints = {};
  //hints.ai_family = AF_INET6;
  //AddrInfoResult result;
  //ares_getaddrinfo(channel_, "www.google.com.", NULL, &hints, AddrInfoCallback, &result);
  //Process();
  //EXPECT_TRUE(result.done_);
  //EXPECT_EQ(ARES_SUCCESS, result.status_);
  //EXPECT_THAT(result.ai_, IncludesAtLeastNumAddresses(1));
  //EXPECT_THAT(result.ai_, OnlyIncludesAddrType(AF_INET6));
//}

//VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetAddrInfoUnspec) {
  //struct ares_addrinfo_hints hints = {};
  //hints.ai_family = AF_UNSPEC;
  //AddrInfoResult result;
  //ares_getaddrinfo(channel_, "www.google.com.", NULL, &hints, AddrInfoCallback, &result);
  //Process();
  //EXPECT_TRUE(result.done_);
  //EXPECT_EQ(ARES_SUCCESS, result.status_);
  //EXPECT_THAT(result.ai_, IncludesAtLeastNumAddresses(2));
  //EXPECT_THAT(result.ai_, IncludesAddrType(AF_INET6));
  //EXPECT_THAT(result.ai_, IncludesAddrType(AF_INET));
//}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetHostByNameV4) {
  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
  EXPECT_LT(0, (int)result.host_.addrs_.size());
  EXPECT_EQ(AF_INET, result.host_.addrtype_);
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetHostByNameV6) {
  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET6, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
  EXPECT_LT(0, (int)result.host_.addrs_.size());
  EXPECT_EQ(AF_INET6, result.host_.addrtype_);
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetHostByAddrV4) {
  HostResult result;
  ares_gethostbyaddr(channel_, cflare_addr4, sizeof(cflare_addr4), AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
  EXPECT_LT(0, (int)result.host_.addrs_.size());
  EXPECT_EQ(AF_INET, result.host_.addrtype_);
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetHostByAddrV6) {
  HostResult result;
  ares_gethostbyaddr(channel_, cflare_addr6, sizeof(cflare_addr6), AF_INET6, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
  EXPECT_LT(0, (int)result.host_.addrs_.size());
  EXPECT_EQ(AF_INET6, result.host_.addrtype_);
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetHostByNameFile) {
  struct hostent *host = nullptr;

  // Still need a channel even to query /etc/hosts.
  EXPECT_EQ(ARES_ENOTFOUND,
            ares_gethostbyname_file(nullptr, "localhost", AF_INET, &host));

  int rc = ares_gethostbyname_file(channel_, "bogus.mcname", AF_INET, &host);
  EXPECT_EQ(nullptr, host);
  EXPECT_EQ(ARES_ENOTFOUND, rc);

  rc = ares_gethostbyname_file(channel_, "localhost", AF_INET, &host);
  if (rc == ARES_SUCCESS) {
    EXPECT_NE(nullptr, host);
    ares_free_hostent(host);
  }
}

TEST_P(DefaultChannelModeTest, LiveGetLocalhostByNameV4) {
  HostResult result;
  ares_gethostbyname(channel_, "localhost", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  if (result.status_ != ARES_ECONNREFUSED) {
    EXPECT_EQ(ARES_SUCCESS, result.status_);
    EXPECT_EQ(1, (int)result.host_.addrs_.size());
    EXPECT_EQ(AF_INET, result.host_.addrtype_);
    EXPECT_NE(std::string::npos, result.host_.name_.find("localhost"));
  }
}

TEST_P(DefaultChannelModeTest, LiveGetLocalhostByNameIPV6) {
  HostResult result;
  ares_gethostbyname(channel_, "::1", AF_INET6, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  if (result.status_ != ARES_ENOTFOUND) {
    EXPECT_EQ(ARES_SUCCESS, result.status_);
    EXPECT_EQ(1, (int)result.host_.addrs_.size());
    EXPECT_EQ(AF_INET6, result.host_.addrtype_);
    std::stringstream ss;
    ss << HostEnt(result.host_);
    EXPECT_EQ("{'::1' aliases=[] addrs=[0000:0000:0000:0000:0000:0000:0000:0001]}", ss.str());
  }
}

TEST_P(DefaultChannelModeTest, LiveGetLocalhostFailFamily) {
  HostResult result;
  ares_gethostbyname(channel_, "127.0.0.1", AF_INET+AF_INET6, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_ENOTIMP, result.status_);
}

TEST_P(DefaultChannelModeTest, LiveGetLocalhostByAddrV4) {
  HostResult result;
  struct in_addr addr;
  addr.s_addr = htonl(INADDR_LOOPBACK);
  ares_gethostbyaddr(channel_, &addr, sizeof(addr), AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  if (result.status_ != ARES_ENOTFOUND) {
    EXPECT_EQ(ARES_SUCCESS, result.status_);
    EXPECT_LT(0, (int)result.host_.addrs_.size());
    EXPECT_EQ(AF_INET, result.host_.addrtype_);
    // oddly, travis does not resolve to localhost, but a random hostname starting with travis-job
    if (result.host_.name_.find("travis-job") == std::string::npos) {
        EXPECT_NE(std::string::npos,
                  result.host_.name_.find("localhost"));
    }
  }
}

TEST_P(DefaultChannelModeTest, LiveGetLocalhostByAddrV6) {
  HostResult result;
  struct in6_addr addr;
  memset(&addr, 0, sizeof(addr));
  addr.s6_addr[15] = 1;  // in6addr_loopback
  ares_gethostbyaddr(channel_, &addr, sizeof(addr), AF_INET6, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  if (result.status_ != ARES_ENOTFOUND) {
    EXPECT_EQ(ARES_SUCCESS, result.status_);
    EXPECT_LT(0, (int)result.host_.addrs_.size());
    EXPECT_EQ(AF_INET6, result.host_.addrtype_);
    const std::string& name = result.host_.name_;
    EXPECT_TRUE(std::string::npos != name.find("localhost") ||
                std::string::npos != name.find("ip6-loopback"));
  }
}

TEST_P(DefaultChannelModeTest, LiveGetHostByAddrFailFamily) {
  HostResult result;
  unsigned char addr[4] = {8, 8, 8, 8};
  ares_gethostbyaddr(channel_, addr, sizeof(addr), AF_INET6+AF_INET,
                     HostCallback, &result);
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_ENOTIMP, result.status_);
}

TEST_P(DefaultChannelModeTest, LiveGetHostByAddrFailAddrSize) {
  HostResult result;
  unsigned char addr[4] = {8, 8, 8, 8};
  ares_gethostbyaddr(channel_, addr, sizeof(addr) - 1, AF_INET,
                     HostCallback, &result);
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_ENOTIMP, result.status_);
}

INSTANTIATE_TEST_SUITE_P(Modes, DefaultChannelModeTest,
                        ::testing::Values("f", "b", "fb", "bf"));
