#include "ares-test.h"
#include "dns-proto.h"
#include <fcntl.h>
#include <unistd.h>

HostEnt::HostEnt(const struct hostent *hostent) : addrtype_(-1) {
  if (!hostent)
    return;

  if (hostent->h_name)
    name_ = hostent->h_name;

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

IMPL_SHIM(void, ares_set_socket_functions, (ares_channel_t *channel, const struct ares_socket_functions *funcs, void *user_data), (channel, funcs, user_data));
IMPL_SHIM(void, ares_gethostbyname, (ares_channel_t *channel, const char *name, int family, ares_host_callback callback, void *arg), (channel, name, family, callback, arg));
IMPL_SHIM(int, ares_init_options, (ares_channel_t **channelptr, const struct ares_options *options, int optmask), (channelptr, options, optmask));
IMPL_SHIM(void, ares_destroy, (ares_channel_t *channel), (channel));
IMPL_SHIM(struct timeval *, ares_timeout, (ares_channel_t *channel, struct timeval *maxtv, struct timeval *tv), (channel, maxtv, tv));
IMPL_SHIM(void, ares_cancel, (ares_channel_t *channel), (channel));
IMPL_SHIM(void, ares_process, (ares_channel_t *channel, fd_set *read_fds, fd_set *write_fds), (channel, read_fds, write_fds));
IMPL_SHIM(int, ares_fds, (ares_channel_t *channel, fd_set *read_fds, fd_set *write_fds), (channel, read_fds, write_fds));

struct timeval ares__tvnow(void)
{
  struct timeval  now;
  struct timespec tsnow;
  if (0 == clock_gettime(CLOCK_MONOTONIC, &tsnow)) {
    now.tv_sec  = tsnow.tv_sec;
    now.tv_usec = (int)(tsnow.tv_nsec / 1000);
  }
  else {
    now.tv_sec  = (long)time(NULL);
    now.tv_usec = 0;
  }
  return now;
}

void ares__timeval_remaining(struct timeval       *remaining,
                             const struct timeval *now,
                             const struct timeval *tout)
{
  memset(remaining, 0, sizeof(*remaining));

  /* Expired! */
  if (tout->tv_sec < now->tv_sec ||
      (tout->tv_sec == now->tv_sec && tout->tv_usec < now->tv_usec)) {
    return;
  }

  remaining->tv_sec = tout->tv_sec - now->tv_sec;
  if (tout->tv_usec < now->tv_usec) {
    remaining->tv_sec  -= 1;
    remaining->tv_usec  = (tout->tv_usec + 1000000) - now->tv_usec;
  } else {
    remaining->tv_usec = tout->tv_usec - now->tv_usec;
  }
}

void ProcessWork(ares_channel_t *channel,
                 std::function<std::set<ares_socket_t>()> get_extrafds,
                 std::function<void(ares_socket_t)> process_extra,
                 unsigned int cancel_ms) {
  int nfds, count;
  fd_set readers, writers;

#ifndef CARES_SYMBOL_HIDING
  struct timeval tv_begin  = ares__tvnow();
  struct timeval tv_cancel = tv_begin;

  if (cancel_ms) {
    tv_cancel.tv_sec  += (cancel_ms / 1000);
    tv_cancel.tv_usec += ((cancel_ms % 1000) * 1000);
  }
#else
  if (cancel_ms) {
    std::cerr << "library built with symbol hiding, can't test with cancel support" << std::endl;
    return;
  }
#endif

  while (true) {
#ifndef CARES_SYMBOL_HIDING
    struct timeval  tv_now = ares__tvnow();
    struct timeval  tv_remaining;
#endif
    struct timeval  tv;
    struct timeval *tv_select;

    // Retrieve the set of file descriptors that the library wants us to monitor.
    FD_ZERO(&readers);
    FD_ZERO(&writers);
    nfds = ares_fds(channel, &readers, &writers);
    if (nfds == 0)  // no work left to do in the library
      return;

    // Add in the extra FDs if present.
    std::set<ares_socket_t> extrafds = get_extrafds();
    for (ares_socket_t extrafd : extrafds) {
      FD_SET(extrafd, &readers);
      if (extrafd >= (ares_socket_t)nfds) {
        nfds = (int)extrafd + 1;
      }
    }

    /* If ares_timeout returns NULL, it means there are no requests in queue,
     * so we can break out */
    tv_select = ares_timeout(channel, NULL, &tv);
    if (tv_select == NULL)
      return;

#ifndef CARES_SYMBOL_HIDING
    if (cancel_ms) {
      unsigned int remaining_ms;
      ares__timeval_remaining(&tv_remaining,
                              &tv_now,
                              &tv_cancel);
      remaining_ms = (unsigned int)((tv_remaining.tv_sec * 1000) + (tv_remaining.tv_usec / 1000));
      if (remaining_ms == 0) {
        ares_cancel(channel);
        cancel_ms = 0; /* Disable issuing cancel again */
      } else {
        /* Recalculate proper timeout since we also have a cancel to wait on */
        tv_select = ares_timeout(channel, &tv_remaining, &tv);
      }
    }
#endif

    count = select(nfds, &readers, &writers, nullptr, tv_select);
    if (count < 0) {
      fprintf(stderr, "select() failed, errno %d\n", errno);
      return;
    }

    // Let the library process any activity.
    ares_process(channel, &readers, &writers);

    // Let the provided callback process any activity on the extra FD.
    for (ares_socket_t extrafd : extrafds) {
      if (FD_ISSET(extrafd, &readers)) {
        process_extra(extrafd);
      }
    }
  }
}

std::set<ares_socket_t> NoExtraFDs() {
  return std::set<ares_socket_t>();
}

void DefaultChannelModeTest::Process(unsigned int cancel_ms) {                                                                             
  ProcessWork(channel_, NoExtraFDs, nullptr, cancel_ms);
}

static int configure_socket(ares_socket_t s) {
  int flags;
  flags = fcntl(s, F_GETFL, 0);
  return fcntl(s, F_SETFL, flags | O_NONBLOCK);
}

const struct ares_socket_functions VirtualizeIO::default_functions = {
  [](int af, int type, int protocol, void *) -> ares_socket_t {
    auto s = ::socket(af, type, protocol);
    if (s == ARES_SOCKET_BAD) {
      return s;
    }
    if (configure_socket(s) != 0) {
      close(s);
      return ares_socket_t(-1);
    }
    return s;
  },
  NULL,
  NULL,
  NULL,
  NULL
};

VirtualizeIO::VirtualizeIO(ares_channel_t *c)
  : channel_(c)
{
  ares_set_socket_functions(channel_, &default_functions, 0);
}

VirtualizeIO::~VirtualizeIO() {
  ares_set_socket_functions(channel_, 0, 0);
}

void HostCallback(void *data, int status, int timeouts,
                  struct hostent *hostent) {
  EXPECT_NE(nullptr, data);
  if (data == nullptr)
    return;

  HostResult* result = reinterpret_cast<HostResult*>(data);
  result->done_ = true;
  result->status_ = status;
  result->timeouts_ = timeouts;
  if (hostent)
    result->host_ = HostEnt(hostent);
}
