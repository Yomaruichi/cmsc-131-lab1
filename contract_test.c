/*
 * contract_test.c - the checks the stdout comparison cannot make.
 *
 * run_tests.sh compares decoded output against a fixture, one header at a
 * time. That catches a wrong decode. It cannot see an encode path that
 * loses a field, because nothing prints the encoded bytes. It cannot see a
 * routine that leaves a callee-saved register changed, because the driver
 * never reads one. It cannot see a checksum that folds the carry once
 * when the sum needs it twice, because no sample is large enough.
 *
 * This program makes three checks:
 *
 *   1. Round trip. Every header that tests/manifest.txt marks valid is
 *      decoded into the struct and encoded back into a fresh buffer. The
 *      twenty bytes must be identical to the file. A valid header you add
 *      to the manifest joins this check.
 *   2. Checksum vector. A crafted header whose word sum is 0x8FFFF needs
 *      the end-around carry folded twice. The routine must return 0xFFF7.
 *      A routine that folds once returns 0xFFF8.
 *   3. Register discipline. The wrapper calls each routine with sentinel
 *      values in ebx, esi, and edi. All three must return unchanged. ebp
 *      must return unchanged. The stack pointer must be back where the
 *      call left it. That is the cdecl contract, all five parts of it.
 *
 * It exits 0 when every check passes and 1 otherwise. The starter provides
 * this file and contract_regs.asm, which makes check 3 possible. Do not
 * modify either one. The grader compares your fork against the starter,
 * so an edit appears as a diff in the open.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cdecl.h"

/*
 * The field struct, copied from driver.c so this file stands alone. The
 * offsets are the contract the assembly routines are written against.
 * Keep this definition identical to the one in driver.c.
 */
struct ipv4_fields {
    unsigned int version;        /* 4 bits  */
    unsigned int ihl;            /* 4 bits  */
    unsigned int dscp;           /* 6 bits  */
    unsigned int ecn;            /* 2 bits  */
    unsigned int total_length;   /* 16 bits */
    unsigned int identification; /* 16 bits */
    unsigned int flags;          /* 3 bits  */
    unsigned int fragment_offset;/* 13 bits */
    unsigned int ttl;            /* 8 bits  */
    unsigned int protocol;       /* 8 bits  */
    unsigned int checksum;       /* 16 bits */
    unsigned char src[4];        /* 32 bits */
    unsigned char dst[4];        /* 32 bits */
};

void PRE_CDECL decode_header(unsigned char *hdr, struct ipv4_fields *out) POST_CDECL;
void PRE_CDECL encode_header(struct ipv4_fields *in, unsigned char *hdr) POST_CDECL;
unsigned short PRE_CDECL ip_checksum(unsigned char *hdr, int len) POST_CDECL;

int PRE_CDECL check_decode_registers(unsigned char *hdr, struct ipv4_fields *out) POST_CDECL;
int PRE_CDECL check_encode_registers(struct ipv4_fields *in, unsigned char *hdr) POST_CDECL;
int PRE_CDECL check_checksum_registers(unsigned char *hdr, int len) POST_CDECL;

/*
 * The valid headers come from tests/manifest.txt. Each line of that file
 * holds a name and a class, `valid` or `invalid`. Every valid header must
 * survive a decode and an encode. The manifest is the one list run_tests.sh
 * and this program share, so both test a header added there.
 */
#define MAX_SAMPLES 64
#define MANIFEST "tests/manifest.txt"

static char valid_samples[MAX_SAMPLES][64];
static size_t valid_count = 0;

static int read_manifest(void)
{
    FILE *f = fopen(MANIFEST, "r");
    char line[128];
    char name[64];
    char kind[16];

    if (!f) {
        printf("FAIL  cannot open %s\n", MANIFEST);
        return 0;
    }
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
        if (sscanf(line, "%63s %15s", name, kind) != 2) {
            printf("FAIL  %s: cannot read line: %s", MANIFEST, line);
            fclose(f);
            return 0;
        }
        if (strcmp(kind, "valid") == 0) {
            if (valid_count == MAX_SAMPLES) {
                printf("FAIL  %s: more than %d valid headers\n", MANIFEST, MAX_SAMPLES);
                fclose(f);
                return 0;
            }
            snprintf(valid_samples[valid_count], sizeof(valid_samples[0]), "tests/%s.bin", name);
            valid_count++;
        } else if (strcmp(kind, "invalid") != 0) {
            printf("FAIL  %s: %s is neither valid nor invalid: %s\n", MANIFEST, name, kind);
            fclose(f);
            return 0;
        }
    }
    fclose(f);
    if (valid_count == 0) {
        printf("FAIL  %s lists no valid header\n", MANIFEST);
        return 0;
    }
    return 1;
}

/*
 * Ten 16-bit big-endian words: nine of 0xFFFF and one of 0x0008. The sum is
 * 0x8FFFF. The first fold gives 0xFFFF + 0x8 = 0x10007. The second gives
 * 0x0007 + 0x1 = 0x0008. NOT 0x0008 is 0xFFF7.
 */
static unsigned char fold_twice[20] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x08,
};

static int failures = 0;

static int read_file(const char *path, unsigned char *buf)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        printf("FAIL  cannot open %s\n", path);
        return 0;
    }
    size_t got = fread(buf, 1, 20, f);
    fclose(f);
    if (got != 20) {
        printf("FAIL  %s: read %u of 20 bytes\n", path, (unsigned)got);
        return 0;
    }
    return 1;
}

/*
 * report_mask - print the verdict for one routine. The mask comes from
 * contract_regs.asm: bit 0 ebx, bit 1 esi, bit 2 edi, bit 3 esp, bit 4
 * ebp. The FAIL line names every violated obligation.
 */
static void report_mask(const char *routine, int mask)
{
    if (mask == 0) {
        printf("ok    %s keeps ebx, esi, edi, ebp, and esp\n", routine);
        return;
    }
    printf("FAIL  %s changed", routine);
    if (mask & 1) printf(" ebx");
    if (mask & 2) printf(" esi");
    if (mask & 4) printf(" edi");
    if (mask & 16) printf(" ebp");
    if (mask & 8) printf(" esp (the stack pointer is not where the call left it)");
    printf("\n");
    failures++;
}

int main(void)
{
    size_t count;
    unsigned char original[20];
    unsigned char rebuilt[20];
    struct ipv4_fields fields;
    size_t i;
    int k;
    int mask;
    unsigned short got;

    /* Check 1: every valid header survives the round trip, byte for byte. */
    if (!read_manifest()) {
        printf("\n1 contract check(s) failed.\n");
        return 1;
    }
    count = valid_count;
    for (i = 0; i < count; i++) {
        if (!read_file(valid_samples[i], original)) {
            failures++;
            continue;
        }
        memset(&fields, 0, sizeof(fields));
        memset(rebuilt, 0xA5, sizeof(rebuilt));
        decode_header(original, &fields);
        encode_header(&fields, rebuilt);

        for (k = 0; k < 20; k++) {
            if (original[k] != rebuilt[k]) {
                printf("FAIL  %s round trip: byte %d is 0x%02X, rebuilt 0x%02X\n",
                       valid_samples[i], k, original[k], rebuilt[k]);
                failures++;
                break;
            }
        }
        if (k == 20) {
            printf("ok    %s round trip\n", valid_samples[i]);
        }
    }

    /* Check 2: the checksum vector that needs the carry folded twice. */
    got = ip_checksum(fold_twice, 20);
    if (got == 0xFFF7) {
        printf("ok    checksum vector (0x8FFFF folds twice)\n");
    } else {
        printf("FAIL  checksum vector: want 0xFFF7, got 0x%04X\n", got);
        if (got == 0xFFF8) {
            printf("      that is what a single fold produces\n");
        }
        failures++;
    }

    /* Check 3: the register discipline of all three routines, on the first
     * valid header. */
    if (read_file(valid_samples[0], original)) {
        memset(&fields, 0, sizeof(fields));
        mask = check_decode_registers(original, &fields);
        report_mask("decode_header", mask);

        memset(rebuilt, 0, sizeof(rebuilt));
        mask = check_encode_registers(&fields, rebuilt);
        report_mask("encode_header", mask);

        mask = check_checksum_registers(original, 20);
        report_mask("ip_checksum", mask);
    } else {
        failures++;
    }

    printf("\n");
    if (failures == 0) {
        printf("The contract checks passed.\n");
        return 0;
    }
    printf("%d contract check(s) failed.\n", failures);
    return 1;
}
