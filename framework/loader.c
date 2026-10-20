#include <loader.h>
#include <common.h>

static int names_match(const char* left, const char* right) {
    while (*left && *right) {
        if (*left++ != *right++) return 0;
    }
    return *left == *right;
}

neolk_word loader_run_payload(
    const char* name, neolk_call original,
    neolk_word x0, neolk_word x1, neolk_word x2, neolk_word x3,
    neolk_word x4, neolk_word x5, neolk_word x6, neolk_word x7) {
    printf("[neolk] loading \"%s\"\n", name);
    for (unsigned long long i = 0; i < neolk_payload_count; ++i) {
        if (names_match(name, neolk_payloads[i].name)) {
            neolk_payloads[i].main(x0, x1, x2, x3, x4, x5, x6, x7);
            break;
        }
    }
    return original(x0, x1, x2, x3, x4, x5, x6, x7);
}
