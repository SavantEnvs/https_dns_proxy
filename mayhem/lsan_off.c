// Disable LeakSanitizer at build time for every fuzz and -standalone binary. Leaks are not the
// bug class this integration fuzzes for (ASan memory errors and UBSan stay fully on).
int __lsan_is_turned_off(void) { return 1; }
