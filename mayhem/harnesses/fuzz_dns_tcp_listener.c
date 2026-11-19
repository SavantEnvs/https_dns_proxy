// Fuzz the DNS-over-TCP listener (src/dns_listener_tcp.c) through its public interface:
// dns_tcp_listener_create() on 127.0.0.1, one loopback client that writes the fuzz bytes as a
// stream, and the listener's respond / request_complete / stop / destroy vtable, used the way
// doh_proxy.c uses them. Reaches accept_cb, read_cb (length-prefix framing, input buffer growth),
// get_dns_request, dispatch_client_requests (16-request pipeline limit), tcp_respond (output
// queue limit), flush_client_output, tcp_request_complete (read resume) and remove_client.
//
// Input layout:
//   byte 0      mode bits
//                 0x01 answer each request (else complete it without an answer: the
//                      "awaiting bootstrap" / fetch-limit paths of doh_proxy.c)
//                 0x02 hold requests until the client has sent everything (pipelining, reaches
//                      the 16-request limit and the read-resume path)
//                 0x04 stop the listener (graceful drain) before the client closes
//                 0x08 send the stream in one write instead of length-prefixed chunks
//                 0x10 complete the request synchronously inside the callback when not
//                      answering (doh_proxy.c does that while awaiting bootstrap)
//                 0x60 answer size: request length << (2 * ((mode >> 5) & 3)), max 65535
//   bytes 1..   the TCP byte stream. Unless 0x08: a sequence of [n][n bytes] chunks, each sent
//               by its own write with a loop pump in between.
//
// Requests are answered after ev_run() returns, never from inside the request callback: the
// real proxy answers asynchronously from the libcurl completion, so a respond() issued inside
// dispatch_client_requests() would be a harness-made path.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dns_listener_tcp.h"
#include "fuzz_common.h"

enum {
  M_ANSWER = 0x01,
  M_HOLD = 0x02,
  M_STOP = 0x04,
  M_ONE_WRITE = 0x08,
  M_SYNC_COMPLETE = 0x10,
  MAX_QUEUED = 256,
  MAX_RESP = 65535,
};

typedef struct {
  struct sockaddr_storage raddr;
  uint64_t id;
  char *req;
  size_t len;
} queued_t;

static struct ev_loop *loop;
static struct addrinfo listen_ai;
static struct sockaddr_in listen_sa;
static queued_t queue[MAX_QUEUED];
static size_t nqueued;
static uint8_t mode;

static void request_cb(void *ctx, dns_listener_t *listener, struct sockaddr *raddr,
                       uint64_t connection_id, char *dns_req, size_t dns_req_len) {
  (void)ctx;
  if (!(mode & M_ANSWER) && (mode & M_SYNC_COMPLETE)) {
    listener->request_complete(listener, raddr, connection_id);
    free(dns_req);
    return;
  }
  if (nqueued == MAX_QUEUED) {  // cannot happen: one client holds at most 16 requests
    abort();
  }
  queued_t *q = &queue[nqueued++];
  memset(&q->raddr, 0, sizeof(q->raddr));
  memcpy(&q->raddr, raddr, sizeof(struct sockaddr_in));
  q->id = connection_id;
  q->req = dns_req;
  q->len = dns_req_len;
}

// Answer (or just complete) every queued request; returns how many there were.
static size_t answer_queued(dns_listener_t *l) {
  size_t n = nqueued;
  for (size_t i = 0; i < n; i++) {
    queued_t *q = &queue[i];
    if (mode & M_ANSWER) {
      size_t resp_len = q->len << (2 * ((mode >> 5) & 3));
      if (resp_len > MAX_RESP) {
        resp_len = MAX_RESP;
      }
      char *resp = malloc(resp_len);
      if (resp == NULL) {
        abort();
      }
      for (size_t j = 0; j < resp_len; j++) {
        resp[j] = q->req[j % q->len];
      }
      resp[2] = (char)(resp[2] | 0x80);  // QR: this is a response
      l->respond(l, (struct sockaddr *)&q->raddr, q->id, q->req, q->len, resp, resp_len);
      free(resp);
    }
    l->request_complete(l, (struct sockaddr *)&q->raddr, q->id);
    free(q->req);
  }
  nqueued = 0;
  return n;
}

static void send_all(int fd, const uint8_t *p, size_t n) {
  // Non-blocking: once the listener stops reading (16 requests pending) the kernel buffer
  // fills, and what does not fit is dropped rather than deadlocking the single-threaded harness.
  while (n > 0) {
    ssize_t w = send(fd, p, n, MSG_NOSIGNAL | MSG_DONTWAIT);
    if (w <= 0) {
      return;
    }
    p += w;
    n -= (size_t)w;
  }
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  fuzz_logging_init();
  loop = ev_loop_new(EVFLAG_AUTO);
  if (loop == NULL) {
    abort();
  }
  fuzz_loopback_addrinfo(&listen_ai, &listen_sa, SOCK_STREAM, fuzz_pick_port(SOCK_STREAM));
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) {
    return -1;
  }
  mode = data[0];
  data++;
  size--;
  nqueued = 0;

  dns_listener_t *l = dns_tcp_listener_create(loop, &listen_ai, 2, request_cb, NULL);

  int c = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (c < 0 || connect(c, (struct sockaddr *)&listen_sa, sizeof(listen_sa)) != 0) {
    abort();
  }
  fuzz_set_nonblock(c);
  fuzz_pump(loop, 2);  // accept_cb

  if (mode & M_ONE_WRITE) {
    send_all(c, data, size);
    fuzz_pump(loop, 2);
    fuzz_drain(c);
  } else {
    size_t i = 0;
    while (i < size) {
      size_t n = data[i++];
      if (n > size - i) {
        n = size - i;
      }
      send_all(c, data + i, n);
      i += n;
      fuzz_pump(loop, 2);
      fuzz_drain(c);
      if (!(mode & M_HOLD)) {
        answer_queued(l);
        fuzz_drain(c);
      }
    }
  }

  // Let the listener consume everything buffered (up to 64 KiB per frame, 4 KiB per read),
  // answering as the proxy would, until three rounds in a row produce no request.
  for (int idle = 0, rounds = 0; idle < 3 && rounds < 1024; rounds++) {
    fuzz_pump(loop, 1);
    fuzz_drain(c);
    idle = answer_queued(l) ? 0 : idle + 1;
    fuzz_drain(c);
  }

  if (mode & M_STOP) {
    l->stop(l);
  }
  shutdown(c, SHUT_WR);  // EOF: read_eof path
  for (int idle = 0, rounds = 0; idle < 3 && rounds < 1024; rounds++) {
    fuzz_pump(loop, 1);
    fuzz_drain(c);
    idle = answer_queued(l) ? 0 : idle + 1;
    fuzz_drain(c);
  }

  // Abortive close (RST) so no TIME_WAIT entry outlives the input.
  struct linger lg = {1, 0};
  setsockopt(c, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
  close(c);
  fuzz_pump(loop, 2);
  answer_queued(l);
  fuzz_pump(loop, 1);

  l->stop(l);  // main.c always stops a listener before destroying it (destroy alone leaves
               // the accept watcher armed); stop() is idempotent if mode 0x04 already ran it
  l->destroy(l);
  // Requests still queued here belong to a destroyed listener; drop them like a shutdown would.
  for (size_t i = 0; i < nqueued; i++) {
    free(queue[i].req);
  }
  nqueued = 0;
  fuzz_pump(loop, 1);
  return 0;
}
