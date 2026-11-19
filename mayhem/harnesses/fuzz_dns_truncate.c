// Fuzz dns_truncate_for_udp() (src/dns_truncate.h): fit a DoH response into the UDP size the
// client's request advertises (EDNS0 OPT, else 512). Parses the untrusted request and the
// untrusted resolver response with c-ares, drops records and re-encodes.
//
// Input layout:
//   bytes 0..1  big-endian length N of the request
//   bytes 2..   N bytes of request, then the response (the rest)
//
// Preconditions from the callers' contract: both buffers are at least a DNS header long.
// dns_listener_udp.c's watcher_cb drops requests shorter than DNS_HEADER_LENGTH, and
// udp_respond() drops responses shorter than DNS_HEADER_LENGTH before truncating.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "dns_common.h"
#include "dns_truncate.h"
#include "fuzz_common.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  fuzz_logging_init();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) {
    return -1;
  }
  const size_t req_len = ((size_t)data[0] << 8) | data[1];
  data += 2;
  size -= 2;
  if (req_len < DNS_HEADER_LENGTH || req_len > size ||
      size - req_len < DNS_HEADER_LENGTH) {
    return -1;
  }
  const size_t resp_len = size - req_len;

  // Exact-size heap copies so ASan catches any read or write past either buffer.
  char *req = malloc(req_len);
  char *resp = malloc(resp_len);
  if (req == NULL || resp == NULL) {
    abort();
  }
  memcpy(req, data, req_len);
  memcpy(resp, data + req_len, resp_len);

  size_t new_len = resp_len;
  dns_truncate_for_udp(req, req_len, resp, &new_len);
  if (new_len > resp_len) {
    abort();  // the API only ever shrinks the response in place
  }

  free(req);
  free(resp);
  return 0;
}
