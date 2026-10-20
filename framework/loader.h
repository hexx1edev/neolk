#pragma once

typedef unsigned long long neolk_word;
typedef neolk_word (*neolk_call)(
    neolk_word, neolk_word, neolk_word, neolk_word,
    neolk_word, neolk_word, neolk_word, neolk_word);

struct neolk_payload {
    const char* name;
    neolk_call main;
};

extern const struct neolk_payload neolk_payloads[];
extern const unsigned long long neolk_payload_count;

neolk_word loader_run_payload(
    const char* name, neolk_call original,
    neolk_word x0, neolk_word x1, neolk_word x2, neolk_word x3,
    neolk_word x4, neolk_word x5, neolk_word x6, neolk_word x7);
