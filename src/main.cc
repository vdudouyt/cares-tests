#include <iostream>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <ares.h>
#include <cstddef>
#include <netdb.h>
#include "dns-proto.h"
#include "ares-test.h"

extern "C" {
#include "impl.h"
}

#define ares_parse_a_reply impl.ares_parse_a_reply
#define ares_free_hostent impl.ares_free_hostent

using ::testing::_;
using ::testing::Return;

class IHelloSayer {
public:
   virtual void SayHello() = 0;
};

class MockHelloSayer: public IHelloSayer {
public:
   MOCK_METHOD(void, SayHello, (), (override));
};

TEST(LibraryTest, ParseAReplyOK) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", T_A))
    .add_answer(new DNSARR("example.com", 0x01020304, {2,3,4,5}))
    .add_answer(new DNSAaaaRR("example.com", 0x01020304, {0,0,0,0,0,0,0,0,0,0,0,0,2,3,4,5}));
  std::vector<byte> data = {
    0x12, 0x34,  // qid
    0x84, // response + query + AA + not-TC + not-RD
    0x00, // not-RA + not-Z + not-AD + not-CD + rc=NoError
    0x00, 0x01,  // num questions
    0x00, 0x02,  // num answer RRs
    0x00, 0x00,  // num authority RRs
    0x00, 0x00,  // num additional RRs
    // Question
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,  // type A
    0x00, 0x01,  // class IN
    // Answer 1
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,  // RR type
    0x00, 0x01,  // class IN
    0x01, 0x02, 0x03, 0x04, // TTL
    0x00, 0x04,  // rdata length
    0x02, 0x03, 0x04, 0x05,
    // Answer 2
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x1c,  //  RR type
    0x00, 0x01,  //  class IN
    0x01, 0x02, 0x03, 0x04, // TTL
    0x00, 0x10,  // rdata length
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x04, 0x05,
  };
  EXPECT_EQ(data, pkt.data());
  struct hostent *host = nullptr;
  struct ares_addrttl info[5];
  int count = 5;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_a_reply(data.data(), (int)data.size(),
                                             &host, info, &count));
  EXPECT_EQ(1, count);
  EXPECT_EQ(0x01020304, info[0].ttl);
  unsigned long expected_addr = htonl(0x02030405);
  EXPECT_EQ(expected_addr, info[0].ipaddr.s_addr);
  EXPECT_EQ("2.3.4.5", AddressToString(&(info[0].ipaddr), 4));
  ASSERT_NE(nullptr, host);
  std::stringstream ss;
  ss << HostEnt(host);
  EXPECT_EQ("{'example.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
  ares_free_hostent(host);

  // Repeat without providing a hostent
  EXPECT_EQ(ARES_SUCCESS, ares_parse_a_reply(data.data(), (int)data.size(),
                                             nullptr, info, &count));
  EXPECT_EQ(1, count);
  EXPECT_EQ(0x01020304, info[0].ttl);
  EXPECT_EQ(expected_addr, info[0].ipaddr.s_addr);
  EXPECT_EQ("2.3.4.5", AddressToString(&(info[0].ipaddr), 4));
}

TEST(LibraryTest, ParseMalformedAReply) {
  std::vector<byte> data = {
    0x12, 0x34,  // [0:2) qid
    0x84, // [2] response + query + AA + not-TC + not-RD
    0x00, // [3] not-RA + not-Z + not-AD + not-CD + rc=NoError
    0x00, 0x01,  // [4:6) num questions
    0x00, 0x02,  // [6:8) num answer RRs
    0x00, 0x00,  // [8:10) num authority RRs
    0x00, 0x00,  // [10:12) num additional RRs
    // Question
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // [12:20)
    0x03, 'c', 'o', 'm', // [20,24)
    0x00, // [24]
    0x00, 0x01,  // [25:26) type A
    0x00, 0x01,  // [27:29) class IN
    // Answer 1
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // [29:37)
    0x03, 'c', 'o', 'm', // [37:41)
    0x00, // [41]
    0x00, 0x01,  // [42:44) RR type
    0x00, 0x01,  // [44:46) class IN
    0x01, 0x02, 0x03, 0x04, // [46:50) TTL
    0x00, 0x04,  // [50:52) rdata length
    0x02, 0x03, 0x04, 0x05, // [52,56)
  };
  struct hostent *host = nullptr;
  struct ares_addrttl info[2];
  int count = 2;

  // Invalid RR-len.
  std::vector<byte> invalid_rrlen(data);
  invalid_rrlen[51] = 180;
  EXPECT_EQ(ARES_EBADRESP, ares_parse_a_reply(invalid_rrlen.data(), (int)invalid_rrlen.size(),
                                              &host, info, &count));

  // Truncate mid-question.
  EXPECT_EQ(ARES_EBADRESP, ares_parse_a_reply(data.data(), 26,
                                              &host, info, &count));

  // Truncate mid-answer.
  EXPECT_EQ(ARES_EBADRESP, ares_parse_a_reply(data.data(), 42,
                                              &host, info, &count));
}

TEST(LibraryTest, ParseAReplyNoData) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", T_A));
  std::vector<byte> data = pkt.data();
  struct hostent *host = nullptr;
  struct ares_addrttl info[2];
  int count = 2;
  EXPECT_EQ(ARES_ENODATA, ares_parse_a_reply(data.data(), (int)data.size(),
                                             &host, info, &count));
  EXPECT_EQ(0, count);
  EXPECT_EQ(nullptr, host);

  // Again but with a CNAME.
  pkt.add_answer(new DNSCnameRR("example.com", 200, "c.example.com"));
  data = pkt.data();
  // Expect success as per https://github.com/c-ares/c-ares/commit/2c63440127feed70ccefb148b8f938a2df6c15f8
  EXPECT_EQ(ARES_SUCCESS, ares_parse_a_reply(data.data(), (int)data.size(),
                                             &host, info, &count));
  EXPECT_EQ(0, count);
  EXPECT_NE(nullptr, host);
  std::stringstream ss;
  ss << HostEnt(host);
  EXPECT_EQ("{'c.example.com' aliases=[example.com] addrs=[]}", ss.str());
  ares_free_hostent(host);
}

TEST(LibraryTest, ParseAReplyVariantA) {
  DNSPacket pkt;
  pkt.set_qid(6366).set_rd().set_ra()
    .add_question(new DNSQuestion("mit.edu", T_A))
    .add_answer(new DNSARR("mit.edu", 52, {18,7,22,69}))
    .add_auth(new DNSNsRR("mit.edu", 292, "W20NS.mit.edu"))
    .add_auth(new DNSNsRR("mit.edu", 292, "BITSY.mit.edu"))
    .add_auth(new DNSNsRR("mit.edu", 292, "STRAWB.mit.edu"))
    .add_additional(new DNSARR("STRAWB.mit.edu", 292, {18,71,0,151}));
  struct hostent *host = nullptr;
  struct ares_addrttl info[2];
  int count = 2;
  std::vector<byte> data = pkt.data();
  EXPECT_EQ(ARES_SUCCESS, ares_parse_a_reply(data.data(), (int)data.size(),
                                             &host, info, &count));
  EXPECT_EQ(1, count);
  EXPECT_EQ("18.7.22.69", AddressToString(&(info[0].ipaddr), 4));
  EXPECT_EQ(52, info[0].ttl);
  ares_free_hostent(host);
}

int main(int argc, char **argv) {
    if(argc != 2) {
        fprintf(stderr, "Wrong usage\n");
        exit(-1);
    }
    ::testing::InitGoogleTest(&argc, argv);
    load_cares_impl(argv[1]);
    int res = RUN_ALL_TESTS();
    unload_cares_impl();
    return res;
}
