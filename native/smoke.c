#include <argon2.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    argon2_type types[] = {Argon2_d, Argon2_i, Argon2_id};
    unsigned char raw[32];
    char encoded[256];
    const unsigned char expected[32] = {
        0x4f,0xf5,0xce,0x27,0x69,0xa1,0xd7,0xf4,0xc8,0xa4,0x91,0xdf,0x09,0xd4,0x1a,0x9f,
        0xbe,0x90,0xe5,0xeb,0x02,0x15,0x5a,0x13,0xe4,0xc0,0x1e,0x20,0xcd,0x4e,0xab,0x61
    };
    size_t i;
    /* Argon2 v1.3 upstream known-answer vector: m=256 KiB, t=2, p=2. */
    if (argon2i_hash_raw(2, 256, 2, "password", 8, "somesalt", 8, raw, sizeof(raw)) != ARGON2_OK ||
        memcmp(raw, expected, sizeof(raw)) != 0) {
        fprintf(stderr, "Argon2i known-answer test failed\n");
        return 1;
    }
    for (i = 0; i < sizeof(types) / sizeof(types[0]); ++i) {
        if (argon2_hash(2, 32, 2, "password", 8, "somesalt", 8,
                        raw, sizeof(raw), encoded, sizeof(encoded), types[i],
                        ARGON2_VERSION_13) != ARGON2_OK ||
            argon2_verify(encoded, "password", 8, types[i]) != ARGON2_OK ||
            argon2_verify(encoded, "wrong", 5, types[i]) != ARGON2_VERIFY_MISMATCH) {
            fprintf(stderr, "Argon2 variant %d failed\n", (int)types[i]);
            return 1;
        }
    }
    /* Exercise verification cleanup after partially decoding malformed input. */
    if (argon2_verify("$argon2id$v=19$m=32,t=2,p=2$c29tZXNhbHQ$!", "password", 8,
                      Argon2_id) == ARGON2_OK) {
        fprintf(stderr, "Malformed hash accepted\n");
        return 1;
    }
    return 0;
}
