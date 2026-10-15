#include <stdio.h>
#include <sys/utsname.h>
#if !defined(__aarch64__)
#error "This smoke test requires an actual AArch64 compiler target"
#endif
int main(void) {
    struct utsname info;
    if (uname(&info) != 0) return 2;
    unsigned long long total = 0;
    for (unsigned long long i = 1; i <= 1000; ++i) total += i * i;
    printf("{\"machine\":\"%s\",\"compiled_architecture\":\"aarch64\",\"sum_squares\":%llu}\n", info.machine, total);
    return total == 333833500ULL ? 0 : 3;
}
