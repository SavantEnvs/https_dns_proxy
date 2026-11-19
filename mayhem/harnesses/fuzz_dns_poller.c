// Fuzz the bootstrap-DNS path: dns_poller_init() (src/dns_poller.h) resolving the DoH host
// against a fake bootstrap DNS server on 127.0.0.1 that answers with fuzz bytes, feeding
// doh_proxy_handle_resolver_update() (src/doh_proxy.h) exactly as main.c wires them. Reaches
// timer_cb / sock_state_cb / sock_cb / ares_cb / get_addr_listing in dns_poller.c and
// addr_list_contains / addr_list_reduced / the CURLOPT_RESOLVE rebuild in doh_proxy.c (with
// https_client_reset), via c-ares' real UDP client.
//
// Input layout:
//   byte 0   bit 0: AF_INET only (else AF_UNSPEC: A and AAAA queries)
//            bit 1: two polls on the same proxy (the second compares against the first's list)
//   then     answers: [2-byte big-endian length n][n bytes], used in order, one per query the
//            fake server receives. The server writes the query's transaction ID over the first
//            two bytes, as any DNS server echoes it (c-ares picks a random ID per query, so the
//            input cannot know it); everything else is sent as given.
//
// Each poll ends with dns_poller_cleanup() once the answers run out or the lookup completes,
// so no c-ares retry timer is ever waited on.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#include "dns_poller.h"
#include "doh_proxy.h"
#include "https_client.h"
#include "options.h"
#include "fuzz_common.h"

static struct ev_loop *loop;
static options_t opt;
static https_client_t client;
static int server = -1;
static char bootstrap[32];

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  fuzz_logging_init();
  loop = ev_loop_new(EVFLAG_AUTO);
  if (loop == NULL) {
    abort();
  }
  if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
    abort();
  }
  options_init(&opt);
  https_client_init(&client, &opt, NULL, loop);

  server = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  socklen_t len = sizeof(sa);
  if (server < 0 || bind(server, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
      getsockname(server, (struct sockaddr *)&sa, &len) != 0) {
    abort();
  }
  snprintf(bootstrap, sizeof(bootstrap), "127.0.0.1:%u", ntohs(sa.sin_port));
  return 0;
}

static void drain_server(void) {
  char buf[512];
  while (recv(server, buf, sizeof(buf), 0) > 0) {
  }
}

// One poll: start the poller, answer each query with the next record, stop when the lookup
// completed (request_ongoing drops to 0) or the records ran out.
static void poll_once(doh_proxy_t *proxy, int family, const uint8_t **data, size_t *size) {
  dns_poller_t d;
  memset(&d, 0, sizeof(d));
  // Trailing dot: an absolute name, so /etc/resolv.conf search domains never add queries.
  dns_poller_init(&d, loop, bootstrap, 120, NULL, NULL, "doh.example.", family,
                  doh_proxy_handle_resolver_update, proxy);

  int started = 0;
  for (int round = 0; round < 64; round++) {
    ev_run(loop, EVRUN_NOWAIT);
    if (d.request_ongoing) {
      started = 1;
    } else if (started) {
      break;  // ares_cb ran: lookup finished
    }
    unsigned char q[4096];
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);
    ssize_t qn = recvfrom(server, q, sizeof(q), 0, (struct sockaddr *)&from, &fromlen);
    if (qn < 2) {
      continue;
    }
    if (*size < 2) {
      break;  // no answer left for this query
    }
    size_t n = ((size_t)(*data)[0] << 8) | (*data)[1];
    *data += 2;
    *size -= 2;
    if (n > *size) {
      n = *size;
    }
    unsigned char *a = malloc(n ? n : 1);
    if (a == NULL) {
      abort();
    }
    memcpy(a, *data, n);
    if (n >= 2) {
      memcpy(a, q, 2);  // echo the transaction ID
    }
    *data += n;
    *size -= n;
    (void)sendto(server, a, n, 0, (struct sockaddr *)&from, fromlen);
    free(a);
  }
  dns_poller_cleanup(&d);
  ev_run(loop, EVRUN_NOWAIT);
  drain_server();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) {
    return -1;
  }
  const uint8_t flags = data[0];
  data++;
  size--;
  const int family = (flags & 1) ? AF_INET : AF_UNSPEC;

  drain_server();
  doh_proxy_t *proxy = doh_proxy_create(loop, &client, "https://doh.example/dns-query", NULL);
  poll_once(proxy, family, &data, &size);
  if (flags & 2) {
    poll_once(proxy, family, &data, &size);
  }
  doh_proxy_destroy(proxy);
  return 0;
}
