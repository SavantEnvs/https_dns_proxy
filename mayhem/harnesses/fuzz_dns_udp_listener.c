// Fuzz the DNS-over-UDP listener (src/dns_listener_udp.c) through its public interface:
// dns_udp_listener_create() on 127.0.0.1, a loopback client that sends the fuzzed request
// datagram, and the listener's respond() with a fuzzed DoH answer, the way doh_proxy.c calls it.
// Reaches watcher_cb (recvfrom/MSG_TRUNC size checks), udp_respond and the EDNS0-aware
// truncation in dns_truncate_for_udp (c-ares parse / record removal / re-encode).
//
// Input layout:
//   bytes 0..1  big-endian length N of the request datagram
//   bytes 2..   N bytes: the request datagram the client sends (shorter inputs send what is there)
//   rest        the DoH response body handed to respond() for that request
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dns_listener_udp.h"
#include "fuzz_common.h"

static struct ev_loop *loop;
static struct addrinfo listen_ai;
static struct sockaddr_in listen_sa;

static struct {
  int have;
  struct sockaddr_storage raddr;
  char *req;
  size_t len;
} pending;

static void request_cb(void *ctx, dns_listener_t *listener, struct sockaddr *raddr,
                       uint64_t connection_id, char *dns_req, size_t dns_req_len) {
  (void)ctx;
  (void)listener;
  (void)connection_id;
  if (pending.have) {  // one datagram per input; a second would be a stray from elsewhere
    free(dns_req);
    return;
  }
  pending.have = 1;
  memset(&pending.raddr, 0, sizeof(pending.raddr));
  memcpy(&pending.raddr, raddr, sizeof(struct sockaddr_in));
  pending.req = dns_req;
  pending.len = dns_req_len;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  fuzz_logging_init();
  loop = ev_loop_new(EVFLAG_AUTO);
  if (loop == NULL) {
    abort();
  }
  fuzz_loopback_addrinfo(&listen_ai, &listen_sa, SOCK_DGRAM, fuzz_pick_port(SOCK_DGRAM));
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) {
    return -1;
  }
  size_t req_len = ((size_t)data[0] << 8) | data[1];
  data += 2;
  size -= 2;
  if (req_len > size) {
    req_len = size;
  }
  const uint8_t *resp_src = data + req_len;
  const size_t resp_len = size - req_len;

  memset(&pending, 0, sizeof(pending));
  dns_listener_t *l = dns_udp_listener_create(loop, &listen_ai, request_cb, NULL);

  int c = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (c < 0) {
    abort();
  }
  (void)sendto(c, data, req_len, 0, (struct sockaddr *)&listen_sa, sizeof(listen_sa));
  fuzz_pump(loop, 2);

  if (pending.have) {
    // Exact-size heap copy, as libcurl's response buffer is, so over-reads are caught.
    char *resp = malloc(resp_len ? resp_len : 1);
    if (resp == NULL) {
      abort();
    }
    memcpy(resp, resp_src, resp_len);
    l->respond(l, (struct sockaddr *)&pending.raddr, 0, pending.req, pending.len, resp, resp_len);
    free(resp);
    free(pending.req);
    pending.have = 0;
  }
  fuzz_drain(c);
  close(c);
  l->stop(l);
  l->destroy(l);
  return 0;
}
