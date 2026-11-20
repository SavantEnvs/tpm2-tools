/* Leaks are not the bug class this integration fuzzes for: turn LeakSanitizer off at build time
 * (ASan and UBSan stay fully active). Linked into every sanitized binary by mayhem/build.sh. */
int __lsan_is_turned_off(void) { return 1; }
