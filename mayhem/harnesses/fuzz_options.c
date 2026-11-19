// Fuzz the command line parser, options_parse_args() (src/options.h): getopt loop, parse_int,
// user/group lookup, and the range / URL / interface validation that follows.
//
// Input: NUL-separated arguments (at most 32) after argv[0] = "https_dns_proxy".
//
// Like upstream's own tests/unit/test_options.c, this compiles src/options.c into the harness
// so two environment calls can be replaced:
//   open()  -l <logfile> would create a fuzzer-named file anywhere writable; the mock returns a
//           /dev/null descriptor, so the parser still gets a valid fd and options_cleanup()
//           closes it.
//   sleep() options_parse_args() sleeps 1 s when run as root without dropping privileges; the
//           mock returns at once so a root fuzzer is not throttled to one exec per second.
// Everything else (getopt_long, getpwnam/getgrnam, inet_pton, ...) is the real libc.
#include <arpa/inet.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <net/if.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int fuzz_open(const char *path, int flags, ...) {
  (void)path;
  (void)flags;
  return open("/dev/null", O_WRONLY | O_CLOEXEC);
}

static unsigned int fuzz_sleep(unsigned int seconds) {
  (void)seconds;
  return 0;
}

#define open fuzz_open
#define sleep fuzz_sleep
#include "../../src/options.c"
#undef sleep
#undef open

#include "fuzz_common.h"

enum { MAX_ARGS = 32 };

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  fuzz_logging_init();
  // The parser reports errors with printf(); keep them off the fuzzer's console.
  int fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
  if (fd >= 0) {
    dup2(fd, STDOUT_FILENO);
    close(fd);
  }
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *buf = malloc(size + 1);
  if (buf == NULL) {
    abort();
  }
  memcpy(buf, data, size);
  buf[size] = '\0';

  char *argv[MAX_ARGS + 2];
  int argc = 0;
  argv[argc++] = "https_dns_proxy";
  size_t start = 0;
  for (size_t i = 0; i < size && argc <= MAX_ARGS; i++) {
    if (buf[i] == '\0') {
      argv[argc++] = buf + start;
      start = i + 1;
    }
  }
  if (start < size && argc <= MAX_ARGS) {
    argv[argc++] = buf + start;  // last argument, not NUL-terminated in the input
  }
  argv[argc] = NULL;

  optind = 0;  // glibc: full getopt re-initialisation for every input
  opterr = 0;

  struct Options opt;
  options_init(&opt);
  (void)options_parse_args(&opt, argc, argv);
  options_cleanup(&opt);

  free(buf);
  return 0;
}
