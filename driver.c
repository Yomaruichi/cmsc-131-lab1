/*
 * renpkt - read and write IPv4 headers. Provided to the group. Do not modify.
 *
 * This file does everything that is not bit manipulation. It parses the
 * command line, opens files, and reads the twenty bytes of a header into
 * a buffer. Then it calls the assembly routines below and formats the
 * output. Your defense will use this copy, so what it prints and the
 * struct it fills are the contract. Read this file before writing
 * assembly.
 *
 * The declarations of the three routines you implement follow the struct
 * they share, below the layout comment. Everything else in here is the
 * part the activity is not about.
 *
 * The activity covers one 20-byte IPv4 base header with an IHL of 5. The
 * encoder writes that header and no other. IPv4 options are outside the
 * activity, so the decoder parses no option bytes and the encoder writes
 * none.
 *
 * The driver checks every numeric option against the width of its field.
 * It refuses a value that cannot fit at the command line. The assembler's
 * masks would truncate it in silence. The driver also checks two options
 * against the standard. The total length must be at least 20, because it
 * counts the header itself. RFC 791 reserves the top flag bit, so --flags
 * accepts 0 through 3. --df and --mf set the two bits that exist.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cdecl.h"

/* ------------------------------------------------------------------ */
/* The header layout, once.                                            */
/*                                                                    */
/* Twenty bytes, bit positions counted from the most significant bit  */
/* of each byte:                                                      */
/*                                                                    */
/*   byte  0        1        2        3                               */
/*       +--------+--------+--------+--------+                       */
/*    0  |Ver|IHL |DSCP|ECN|   Total Length  |                       */
/*       +--------+--------+--------+--------+                       */
/*    4  |  Identification |Flg| Frag Offset |                       */
/*       +--------+--------+--------+--------+                       */
/*    8  |  TTL   |Protocol|  Header Checksum|                       */
/*       +--------+--------+--------+--------+                       */
/*   12  |            Source Address         |                       */
/*       +--------+--------+--------+--------+                       */
/*   16  |         Destination Address       |                       */
/*       +--------+--------+--------+--------+                       */
/*                                                                    */
/* The struct below is what decode_header fills and encode_header     */
/* reads. Its layout is deliberate. Every member is an unsigned int,  */
/* so the assembly can store and load them with plain 32-bit moves.   */
/* The two addresses are four octets each. The struct holds them as   */
/* eight separate bytes, so the assembly never has to form a          */
/* multi-byte number out of them.                                     */
/*                                                                    */
/* Offsets (each int member is 4 bytes. The octets are single bytes): */
/*                                                                    */
/*   +0  version           +4  ihl                                     */
/*   +8  dscp              +12 ecn                                     */
/*   +16 total_length      +20 identification                          */
/*   +24 flags             +28 fragment_offset                         */
/*   +32 ttl               +36 protocol                                */
/*   +40 checksum                                                      */
/*   +44 src[0] src[1] src[2] src[3]  (bytes 44, 45, 46, 47)           */
/*   +48 dst[0] dst[1] dst[2] dst[3]  (bytes 48, 49, 50, 51)           */
/*   total size 52 bytes                                               */
/* ------------------------------------------------------------------ */

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

/* The three routines you implement. */
void PRE_CDECL decode_header(unsigned char *hdr, struct ipv4_fields *out) POST_CDECL;
void PRE_CDECL encode_header(struct ipv4_fields *in, unsigned char *hdr) POST_CDECL;
unsigned short PRE_CDECL ip_checksum(unsigned char *hdr, int len) POST_CDECL;

/* ------------------------------------------------------------------ */
/* The rest is driver. Read it for the output format. Leave it as is. */
/* ------------------------------------------------------------------ */

static const char *proto_name(unsigned int p)
{
    switch (p) {
    case 1:  return " (ICMP)";
    case 6:  return " (TCP)";
    case 17: return " (UDP)";
    default: return "";
    }
}

static void print_fields(const struct ipv4_fields *f, int valid)
{
    printf("Version:          %u\n", f->version);
    printf("IHL:              %u (%u bytes)\n", f->ihl, f->ihl * 4);
    printf("DSCP:             %u\n", f->dscp);
    printf("ECN:              %u\n", f->ecn);
    printf("Total Length:     %u\n", f->total_length);
    printf("Identification:   %u\n", f->identification);
    printf("Flags:            %u", f->flags);
    if (f->flags & 0x2) printf(" (DF)");   /* bit 6 of the header */
    if (f->flags & 0x1) printf(" (MF)");   /* bit 5 of the header */
    printf("\n");
    printf("Fragment Offset:  %u\n", f->fragment_offset);
    printf("TTL:              %u\n", f->ttl);
    printf("Protocol:         %u%s\n", f->protocol, proto_name(f->protocol));
    printf("Header Checksum:  0x%04X\n", f->checksum);
    printf("Source:           %u.%u.%u.%u\n", f->src[0], f->src[1], f->src[2], f->src[3]);
    printf("Destination:      %u.%u.%u.%u\n", f->dst[0], f->dst[1], f->dst[2], f->dst[3]);
    printf("Checksum:         %s\n", valid ? "VALID" : "INVALID");
}

static int read_file(const char *path, unsigned char *buf, size_t len)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "renpkt: cannot open %s\n", path);
        return 0;
    }
    size_t got = fread(buf, 1, len, f);
    int bad = (got != len) || ferror(f);
    fclose(f);
    if (bad) {
        fprintf(stderr, "renpkt: %s: expected %u bytes, read %u\n",
                path, (unsigned)len, (unsigned)got);
        return 0;
    }
    return 1;
}

static int write_file(const char *path, const unsigned char *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "renpkt: cannot open %s\n", path);
        return 0;
    }
    size_t wrote = fwrite(buf, 1, len, f);
    int bad = ferror(f);
    fclose(f);
    if (bad || wrote != len) {
        fprintf(stderr, "renpkt: wrote %u of %u bytes to %s\n",
                (unsigned)wrote, (unsigned)len, path);
        return 0;
    }
    return 1;
}

/*
 * parse_u32 - read one whole token as an unsigned decimal number.
 *
 * The token has to be complete. Digits, and nothing but digits. A leading
 * sign, trailing text, an empty token, and a value above limit are all
 * refused. strtoul accepts "12abc" and returns 12, which is how a typo
 * becomes a silently different header. The loop checks the limit after
 * every digit, so the running value cannot overflow before the check.
 */
static int parse_u32(const char *s, unsigned long limit, unsigned int *out)
{
    unsigned long value = 0;
    const char *p = s;

    if (*p == '\0') return 0;
    for (; *p; p++) {
        if (*p < '0' || *p > '9') return 0;
        value = value * 10 + (unsigned long)(*p - '0');
        if (value > limit) return 0;
    }
    *out = (unsigned int)value;
    return 1;
}

/*
 * need_number - parse a numeric option value or stop with a message.
 *
 * The range of its field bounds every numeric option. This function
 * refuses a value outside the range. The usage text and the manual's field
 * table list the ranges.
 */
static unsigned int need_number(const char *name, const char *text, unsigned long low, unsigned long limit)
{
    unsigned int value;
    if (!parse_u32(text, limit, &value) || value < low) {
        fprintf(stderr, "renpkt: %s: bad value: %s (%lu to %lu)\n", name, text, low, limit);
        exit(2);
    }
    return value;
}

/*
 * parse_octets - read a dotted-quad address into four bytes.
 *
 * Four decimal numbers separated by dots, each from 0 to 255, and nothing
 * after the fourth. The parser must consume the whole token. sscanf alone would
 * accept "10.0.0.junk" and "10.0.0.1.2", because it stops after the fourth
 * conversion and never reads the rest.
 */
static int parse_octets(const char *s, unsigned char *out)
{
    const char *p = s;
    int part;

    for (part = 0; part < 4; part++) {
        unsigned long value = 0;
        if (part > 0) {
            if (*p != '.') return 0;
            p++;
        }
        if (*p < '0' || *p > '9') return 0;
        while (*p >= '0' && *p <= '9') {
            value = value * 10 + (unsigned long)(*p - '0');
            if (value > 255) return 0;
            p++;
        }
        out[part] = (unsigned char)value;
    }
    return *p == '\0';
}

/* The options that carry a value, so the message names the option that
 * lacks a value instead of printing the generic usage text. */
static const char *const value_options[] = {
    "-o", "--ttl", "--proto", "--len", "--id", "--dscp", "--ecn",
    "--frag", "--flags", "--src", "--dst", NULL
};

static int takes_value(const char *name)
{
    int k;
    for (k = 0; value_options[k]; k++) {
        if (!strcmp(name, value_options[k])) return 1;
    }
    return 0;
}

static void usage(void)
{
    fprintf(stderr,
        "usage:\n"
        "  renpkt --decode FILE\n"
        "  renpkt --encode [--ttl N] [--proto N] [--len N] [--id N]\n"
        "                 [--dscp N] [--ecn N] [--frag N] [--flags N]\n"
        "                 [--src A.B.C.D] [--dst A.B.C.D] [--df] [--mf] -o FILE\n"
        "\n"
        "  --ttl 0-255   --proto 0-255   --len 20-65535  --id 0-65535\n"
        "  --dscp 0-63   --ecn 0-3       --frag 0-8191   --flags 0-3\n"
        "\n"
        "  --len defaults to 20, the header alone. --flags is DF (2) plus\n"
        "  MF (1). The reserved flag bit stays zero. renpkt refuses 4 to 7.\n");
    exit(2);
}

static void cmd_decode(int argc, char **argv)
{
    if (argc != 3) usage();
    unsigned char hdr[20];
    if (!read_file(argv[2], hdr, 20)) exit(1);

    struct ipv4_fields f;
    memset(&f, 0, sizeof(f));
    decode_header(hdr, &f);

    /*
     * The decode path does not compare a computed checksum against the
     * stored one. Summing a header that already contains its checksum and
     * testing for zero is the shortcut the manual describes. One's
     * complement arithmetic makes a valid header sum to 0x0000. This is
     * ip_checksum's job, so the VALID line reports what it returned.
     */
    int valid = (ip_checksum(hdr, 20) == 0);
    print_fields(&f, valid);
}

static void cmd_encode(int argc, char **argv)
{
    struct ipv4_fields f;
    memset(&f, 0, sizeof(f));
    f.version = 4;
    f.ihl = 5;
    f.total_length = 20;   /* the header alone, until --len says otherwise */

    const char *out = NULL;
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "-o") && i + 1 < argc) {
            out = argv[++i];
        } else if (!strcmp(argv[i], "--ttl") && i + 1 < argc) {
            f.ttl = need_number("--ttl", argv[++i], 0, 255);
        } else if (!strcmp(argv[i], "--proto") && i + 1 < argc) {
            f.protocol = need_number("--proto", argv[++i], 0, 255);
        } else if (!strcmp(argv[i], "--len") && i + 1 < argc) {
            /* The total length counts the header, so 20 is the floor. */
            f.total_length = need_number("--len", argv[++i], 20, 65535);
        } else if (!strcmp(argv[i], "--id") && i + 1 < argc) {
            f.identification = need_number("--id", argv[++i], 0, 65535);
        } else if (!strcmp(argv[i], "--dscp") && i + 1 < argc) {
            f.dscp = need_number("--dscp", argv[++i], 0, 63);
        } else if (!strcmp(argv[i], "--ecn") && i + 1 < argc) {
            f.ecn = need_number("--ecn", argv[++i], 0, 3);
        } else if (!strcmp(argv[i], "--frag") && i + 1 < argc) {
            f.fragment_offset = need_number("--frag", argv[++i], 0, 8191);
        } else if (!strcmp(argv[i], "--flags") && i + 1 < argc) {
            /* Bit 2 of the field is reserved and must be zero, so the
             * field takes 0 to 3: nothing, MF, DF, or both. */
            f.flags = need_number("--flags", argv[++i], 0, 3);
        } else if (!strcmp(argv[i], "--src") && i + 1 < argc) {
            if (!parse_octets(argv[++i], f.src)) {
                fprintf(stderr, "renpkt: bad address: %s\n", argv[i]);
                exit(2);
            }
        } else if (!strcmp(argv[i], "--dst") && i + 1 < argc) {
            if (!parse_octets(argv[++i], f.dst)) {
                fprintf(stderr, "renpkt: bad address: %s\n", argv[i]);
                exit(2);
            }
        } else if (!strcmp(argv[i], "--df")) {
            f.flags |= 0x2;   /* bit 6 of the header is the field's bit 1 */
        } else if (!strcmp(argv[i], "--mf")) {
            f.flags |= 0x1;   /* bit 5 of the header is the field's bit 0 */
        } else if (takes_value(argv[i])) {
            fprintf(stderr, "renpkt: %s needs a value\n", argv[i]);
            exit(2);
        } else {
            usage();
        }
    }
    if (!out) usage();

    unsigned char hdr[20];
    encode_header(&f, hdr);
    if (!write_file(out, hdr, 20)) exit(1);
}

int main(int argc, char **argv)
{
    if (argc < 2) usage();
    if (!strcmp(argv[1], "--decode")) cmd_decode(argc, argv);
    else if (!strcmp(argv[1], "--encode")) cmd_encode(argc, argv);
    else usage();
    return 0;
}
