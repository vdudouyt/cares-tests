#include <iostream>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <ares.h>
#include <cstddef>
#include <netdb.h>

using ::testing::_;
using ::testing::Return;
using byte = uint8_t;

std::string AddressToString(const void* vaddr, int len);

void arestest_strtolower(char *dest, const char *src, size_t dest_size)
{
  size_t len;

  if (dest == NULL)
    return;

  memset(dest, 0, dest_size);

  if (src == NULL)
    return;

  len = strlen(src);
  if (len >= dest_size)
    return;

  for (size_t i = 0; i<len; i++) {
    dest[i] = (char)tolower(src[i]);
  }
}

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

HostEnt::HostEnt(const struct hostent *hostent) : addrtype_(-1) {
  if (!hostent)
    return;

  if (hostent->h_name) {
    // DNS 0x20 may mix case, output as all lower for checks as the mixed case
    // is really more of an internal thing
    char lowername[256];
    arestest_strtolower(lowername, hostent->h_name, sizeof(lowername));
    name_ = lowername;
  }

  if (hostent->h_aliases) {
    char** palias = hostent->h_aliases;
    while (*palias != nullptr) {
      aliases_.push_back(*palias);
      palias++;
    }
  }

  addrtype_ = hostent->h_addrtype;

  if (hostent->h_addr_list) {
    char** paddr = hostent->h_addr_list;
    while (*paddr != nullptr) {
      std::string addr = AddressToString(*paddr, hostent->h_length);
      addrs_.push_back(addr);
      paddr++;
    }
  }
}

std::ostream& operator<<(std::ostream& os, const HostEnt& host) {
  os << "{'";
  if (host.name_.length() > 0) {
    os << host.name_;
  }
  os << "' aliases=[";
  for (size_t ii = 0; ii < host.aliases_.size(); ii++) {
    if (ii > 0) os << ", ";
    os << host.aliases_[ii];
  }
  os << "] ";
  os << "addrs=[";
  for (size_t ii = 0; ii < host.addrs_.size(); ii++) {
    if (ii > 0) os << ", ";
    os << host.addrs_[ii];
  }
  os << "]";
  os << '}';
  return os;
}

class IHelloSayer {
public:
   virtual void SayHello() = 0;
};

class MockHelloSayer: public IHelloSayer {
public:
   MOCK_METHOD(void, SayHello, (), (override));
};

class LolTest: public ::testing::Test {
protected:
   void SetUp() {
      std::cout << "SetUp()" << std::endl;
      value = 10;
   }
   void TearDown() {
      std::cout << "TearDown()" << std::endl;
   }
   int value;
};

// A simple function to test
int Add(int a, int b) {
    return a + b;
}

TEST_F(LolTest, Add) {
    EXPECT_EQ(Add(2, 3), 5);
    EXPECT_NE(Add(2, 2), 5);
    EXPECT_EQ(value, 10);
    MockHelloSayer mock;
    EXPECT_CALL(mock, SayHello());
    mock.SayHello();
}

TEST(LibraryTest, ParseAReplyOK) {
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

std::string HexDump(std::vector<byte> data) {
  std::stringstream ss;
  for (size_t ii = 0; ii < data.size();  ii++) {
    char buffer[2 + 1];
    snprintf(buffer, sizeof(buffer), "%02x", data[ii]);
    ss << buffer;
  }
  return ss.str();
}

std::string HexDump(const byte *data, int len) {                                                                                           
  return HexDump(std::vector<byte>(data, data + len));
}

std::string HexDump(const char *data, int len) {
  return HexDump(reinterpret_cast<const byte*>(data), len);
}

std::string AddressToString(const void* vaddr, int len) {
  const byte* addr = reinterpret_cast<const byte*>(vaddr);
  std::stringstream ss;
  if (len == 4) {
    char buffer[4*4 + 3 + 1];
    snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u",
             (unsigned char)addr[0],
             (unsigned char)addr[1],
             (unsigned char)addr[2],
             (unsigned char)addr[3]);
    ss << buffer;
  } else if (len == 16) {
    for (int ii = 0; ii < 16;  ii+=2) {
      if (ii > 0) ss << ':';
      char buffer[4 + 1];
      snprintf(buffer, sizeof(buffer), "%02x%02x", (unsigned char)addr[ii], (unsigned char)addr[ii+1]);
      ss << buffer;
    }
  } else {
    ss << "!" << HexDump(addr, len) << "!";
  }
  return ss.str();
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
