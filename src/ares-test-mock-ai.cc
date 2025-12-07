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
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "ares-test.h"
#include "dns-proto.h"
#include <sstream>
#include <vector>

class MockUDPChannelTestAI : public MockChannelOptsTest,
                             public ::testing::WithParamInterface<int> {
public:
  MockUDPChannelTestAI() : MockChannelOptsTest(1, GetParam(), false, nullptr, 0)                                                           
  {
  }
};

MATCHER_P(IncludesNumAddresses, n, "") {
  if(!arg)
    return false;
  int cnt = 0;
  for (const ares_addrinfo_node* ai = arg->nodes; ai != NULL; ai = ai->ai_next)
    cnt++;
  return n == cnt;
}

MATCHER_P(IncludesV4Address, address, "") {
  if(!arg)
    return false;
  in_addr addressnum = {};
  if (!ares_inet_pton(AF_INET, address, &addressnum))
    return false; // wrong number format?
  for (const ares_addrinfo_node* ai = arg->nodes; ai != NULL; ai = ai->ai_next) {
    if (ai->ai_family != AF_INET)
      continue;
    if (ai->ai_addrlen != sizeof(struct sockaddr_in))
      continue;
    if (reinterpret_cast<sockaddr_in*>(ai->ai_addr)->sin_addr.s_addr ==
        addressnum.s_addr)
      return true; // found
  }
  return false;
}

MATCHER_P(IncludesV6Address, address, "") {
  if(!arg)
    return false;
  in6_addr addressnum = {};
  if (!ares_inet_pton(AF_INET6, address, &addressnum)) {
    return false; // wrong number format?
  }
  for (const ares_addrinfo_node* ai = arg->nodes; ai != NULL; ai = ai->ai_next) {
    if (ai->ai_family != AF_INET6)
      continue;
    if (ai->ai_addrlen != sizeof(struct sockaddr_in6))
      continue;
    if (!memcmp(
        reinterpret_cast<sockaddr_in6*>(ai->ai_addr)->sin6_addr.s6_addr,
        addressnum.s6_addr, sizeof(addressnum.s6_addr)))
      return true; // found
  }
  return false;
}

// UDP only so mock server doesn't get confused by concatenated requests
TEST_P(MockUDPChannelTestAI, GetAddrInfoParallelLookups) {
  DNSPacket rsp1;
  rsp1.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", T_A))
    .add_answer(new DNSARR("www.google.com", 100, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("www.google.com", T_A))
    .WillByDefault(SetReply(&server_, &rsp1));
  DNSPacket rsp2;
  rsp2.set_response().set_aa()
    .add_question(new DNSQuestion("www.example.com", T_A))
    .add_answer(new DNSARR("www.example.com", 100, {1, 2, 3, 4}));
  ON_CALL(server_, OnRequest("www.example.com", T_A))
    .WillByDefault(SetReply(&server_, &rsp2));

  struct ares_addrinfo_hints hints = {};
  hints.ai_family = AF_INET;
  hints.ai_flags = ARES_AI_NOSORT;
  AddrInfoResult result1;
  ares_getaddrinfo(channel_, "www.google.com.", NULL, &hints, AddrInfoCallback, &result1);
  AddrInfoResult result2;
  ares_getaddrinfo(channel_, "www.example.com.", NULL, &hints, AddrInfoCallback, &result2);
  AddrInfoResult result3;
  ares_getaddrinfo(channel_, "www.google.com.", NULL, &hints, AddrInfoCallback, &result3);
  Process();

  EXPECT_TRUE(result1.done_);
  EXPECT_EQ(result1.status_, ARES_SUCCESS);
  EXPECT_THAT(result1.ai_, IncludesNumAddresses(1));
  EXPECT_THAT(result1.ai_, IncludesV4Address("2.3.4.5"));

  EXPECT_TRUE(result2.done_);
  EXPECT_EQ(result2.status_, ARES_SUCCESS);
  EXPECT_THAT(result2.ai_, IncludesNumAddresses(1));
  EXPECT_THAT(result2.ai_, IncludesV4Address("1.2.3.4"));

  EXPECT_TRUE(result3.done_);
  EXPECT_EQ(result3.status_, ARES_SUCCESS);
  EXPECT_THAT(result3.ai_, IncludesNumAddresses(1));
  EXPECT_THAT(result3.ai_, IncludesV4Address("2.3.4.5"));
}

/*
INSTANTIATE_TEST_SUITE_P(AddressFamiliesAI, MockUDPChannelTestAI,
                        ::testing::ValuesIn(ares::test::families), PrintFamily);
*/
