<!--no-pdf-->
# CMSC 131 Lab 1 Starter

Decode, encode, and checksum 20-byte IPv4 packet headers under a C driver.
The manual is the assignment. This file is the repository's own notes.

## Layout

```text
Makefile            platform preamble and build rules
driver.c            provided: argument parsing and file I/O
cdecl.h             provided: the calling-convention macros
decode.asm          yours
encode.asm          yours
checksum.asm        yours
run_tests.sh        provided: the correctness gate
contract_test.c     provided: the second pass, in C
contract_regs.asm   provided: register discipline checks for contract_test
tests/              provided: the header fixtures, their expected output,
                    and manifest.txt, the list both passes read
LICENSE             CC BY-NC-SA 4.0, inherited from the pcasm material
```

## What to Run

```bash
make
make check
```

`make` builds `renpkt` and `contract_test`. `make check` builds both, then
runs `./run_tests.sh`, which reports each test and exits nonzero when any
of them differ.

The gate has two passes. The first decodes every header listed in
`tests/manifest.txt` and compares the output with `tests/expected/`. The
second is `contract_test`. It decodes and re-encodes every header the
manifest marks valid. It checks a checksum vector that needs the carry
folded twice. It checks that all three routines keep `ebx`, `esi`, `edi`,
and `ebp`, and return with `esp` where the call left it. A program can pass
the first pass and fail the second. That failure is the usual encoder bug.

## Reading a First Run

The assembly files ship as stubs that assemble and link as-is, so the build
works before you write any code. Right now they do nothing useful, which
makes every check fail: `7 of 7 checks differ`. That red run is the correct
starting state for a starter. The badge stays red until you implement the
routines.

## Adding a Header

Put the header in `tests/NAME.bin`. Write the output `renpkt --decode`
must print for it in `tests/expected/NAME.out`. Then add one line to
`tests/manifest.txt`:

```text
NAME valid
```

Use `invalid` for a header with a wrong checksum. A valid header joins the
round trip in `contract_test` as well as the decode pass. The gate fails
and names the file when a `.bin` is not in the manifest, and when a listed
header has no expected file.

## The Driver's Argument Checks

`renpkt --encode` refuses a value its field cannot hold, and two values the
standard forbids. `--len` takes 20 through 65535, because the total length
counts the header. It defaults to 20. `--flags` takes 0 through 3, because
the top bit of the field is reserved and must be zero. `--df` sets 2 and
`--mf` sets 1. A refused option exits with status 2 and writes no file.

## Documentation

The three sections at the end of this file are yours. Complete Design Notes
and Subsystem Ownership before the Week 1 progress report. Complete Quirks
and Issues before the Week 3 progress report. Each section says what it
needs. Leave the rest of this file as it is.

## Fixtures

The provided files are fixtures. The grader compares your fork against the
starter. An edit to `driver.c`, `Makefile`, `run_tests.sh`,
`contract_test.c`, `contract_regs.asm`, or a provided `tests/` file appears
as a diff in the open. Your own headers and manifest lines are additions,
not edits.

---

## Design Notes

Complete this section before the Week 1 progress report. The syllabus asks
for problem analysis, a solution architecture, and an estimated timeline.
Keep each part short. Update it when the plan changes.

### Problem analysis

The tool reads a fixed 20-byte IPv4 base header, decodes the thirteen supported
fields, validates the checksum, and writes a new 20-byte header back out from a
C sourced field struct. Several fields are packed into a single byte or straddle
byte boundaries, and the values travel in network byte order instead of the 
little-endian order used by x86.

Header layout (20 bytes):

```text
byte 0:         Version (4 bits) - Version verification to check how to parse
                IHL (4 bits) - Caps the length
byte 1:         DSCP (6 bits) - traffic prioritization
                ECN (2 bits) - marks packet if congested for  others to back off
bytes 2-3:      Total Length (16-bit big-endian) - full packet size incl. header and payload
bytes 4-5:      Identification (16-bit big-endian) - associates packet with IDs, packet that
                are lost can still be retrieved if since they have the same ID
byte 6:         Flags (3 bits) - Disable fragmentation(DF) among selected packets
byte 7:         Fragment Offset (low 8 bits) - More fragments(MF) to reassemble despite being unordered
byte 8:         TTL - Hop counter to check if the right amount has been forwarded by the routers
byte 9:         Protocol - Shows what's in the payload
bytes 10-11:    Header Checksum (16-bit big-endian) - Detects corruption in the header specifically
bytes 12-15:    Source Address (4 octets) - Who to get packets from
bytes 16-19:    Destination Address (4 octets) - Where to forward the packets next
```

### Solution architecture

The project is split into three assembly routines:

- `decode_header`: reads the 20-byte packet buffer and extracts every field into
  the caller's `struct ipv4_fields`. It uses `movzx`, shifts, masks, and byte-by-byte
  recombines to read each field in the correct bit width and byte order. The
  most delicate case is the 13-bit fragment offset, which is assembled by merging
  bytes 6 and 7 into a 16-bit word and then masking with `0x1FFF`.
  
- `encode_header`: rebuilds the 20-byte header from the field struct. It writes the
  version and IHL into byte 0, packs DSCP and ECN into byte 1, converts each
  16-bit value to network byte order with shifts and masks, and writes the flags
  and offset back into bytes 6-7. The checksum is left with a zero placeholder at
  the end of the header while the checksum routine computes the final value.

- `ip_checksum`: computes the IPv4 one's complement checksum over a byte array of
  the given length. It walks the buffer as 16-bit big-endian words, adds them into
  a 32-bit accumulator, folds the carry repeatedly until the value fits in 16 bits,
  then takes the bitwise NOT and masks to 16 bits.

The C-side struct defines the field layout the driver expects, and every field in
`decode.asm` and `encode.asm` maps directly to those offsets. The offsets are:

```text
+0   version
+4   ihl
+8   dscp
+12  ecn
+16  total_length
+20  identification
+24  flags
+28  fragment_offset
+32  ttl
+36  protocol
+40  checksum
+44  src[0] .. src[3]
+48  dst[0] .. dst[3]
```

This fixed layout gives the assembly code a simple contract: add the base address
in `edi` or `esi`, then use the correct offset for each field. Because the struct
has no padding and every integer member is 4 bytes, all of the offset computations
are aligned and predictable. The address arrays are single bytes, so writing the
source and destination octets is just a byte store at the correct index.

### Timeline

One line per week. Name the subsystem each week finishes and the member
who owns it.

| Week | Goal | Owner |
|---|---|---|
| 1 |  | |
| 2 | | |
| 3 | | |
| 4 | Defense | |

## Subsystem Ownership

Complete this section before the Week 1 progress report. The manual lists
the three subsystems. Each member owns one. In a group of four, two members
share one. The commit history must agree with this table.

| Subsystem | Owner |
|---|---|
| Decode path (`decode.asm`) | John Dave Valentin (Yomaruichi) |
| Encode path (`encode.asm`) | Adrian Moser (AdrianMoser1) |
| Checksum and tests (`checksum.asm`, `tests/`) | Ralph Ryan Escabarte (RalphREE) |

## Quirks and Issues

Complete this section before the Week 3 progress report. The syllabus asks
for documentation of quirks and issues with the complete implementation.
One entry per item. State what happens, what causes it, and what the group
did about it.

### Known issues

- 

### Quirks

- 
