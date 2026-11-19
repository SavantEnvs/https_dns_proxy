// Shared helpers for the https_dns_proxy fuzz harnesses (mayhem/harnesses/).
//
// The proxy's network-facing modules (TCP/UDP listeners, bootstrap DNS poller) only take input
// through real sockets driven by a libev loop, so the harnesses run them exactly as main.c does:
// bind on 127.0.0.1, then feed the fuzz bytes from a loopback peer and pump the loop with
// EVRUN_NOWAIT (no blocking, no timers waited on).
#ifndef FUZZ_COMMON_H
#define FUZZ_COMMON_H

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <ev.h>

#include "logging.h"

// Logs go to /dev/null at DEBUG level, so every DLOG/WLOG format string in the fuzzed code is
// still evaluated (and checked by ASan/UBSan) without flooding the fuzzer's output.
static inline void fuzz_logging_init(void) {
  int fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
  if (fd >= 0) {
    logging_init(fd, LOG_DEBUG, 0);
  }
}

// Reserve a free 127.0.0.1 port of the given socket type for this process: bind port 0, read the
// port the kernel chose, close. The listeners set SO_REUSEADDR, so the same port can be re-bound
// for every input.
static inline uint16_t fuzz_pick_port(int type) {
  int s = socket(AF_INET, type, 0);
  if (s < 0) {
    abort();
  }
  struct sockaddr_in a;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  socklen_t len = sizeof(a);
  if (bind(s, (struct sockaddr *)&a, sizeof(a)) != 0 ||
      getsockname(s, (struct sockaddr *)&a, &len) != 0) {
    abort();
  }
  close(s);
  return ntohs(a.sin_port);
}

// An addrinfo for 127.0.0.1:port, the shape main.c hands to the listener create functions.
static inline void fuzz_loopback_addrinfo(struct addrinfo *ai, struct sockaddr_in *sa,
                                          int socktype, uint16_t port) {
  memset(ai, 0, sizeof(*ai));
  memset(sa, 0, sizeof(*sa));
  sa->sin_family = AF_INET;
  sa->sin_port = htons(port);
  sa->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  ai->ai_family = AF_INET;
  ai->ai_socktype = socktype;
  ai->ai_addr = (struct sockaddr *)sa;
  ai->ai_addrlen = sizeof(*sa);
}

static inline void fuzz_pump(struct ev_loop *loop, int rounds) {
  for (int i = 0; i < rounds; i++) {
    ev_run(loop, EVRUN_NOWAIT);
  }
}

static inline int fuzz_set_nonblock(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  return flags < 0 ? -1 : fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Read and discard whatever the proxy sent back to the peer socket.
static inline void fuzz_drain(int fd) {
  char buf[8192];
  while (recv(fd, buf, sizeof(buf), MSG_DONTWAIT) > 0) {
  }
}

#endif  // FUZZ_COMMON_H
