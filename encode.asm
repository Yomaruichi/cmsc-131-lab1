;
; encode.asm - build a 20-byte IPv4 header from the field struct.
;
; This is your starting point. It assembles and links as-is, so the build
; works before you write any code. Right now it writes nothing, so the
; twenty bytes driver.c saves are whatever the buffer held. Your job is to
; replace that with the construction described below.
;
; The contract, from driver.c:
;
;       unsigned char *hdr        [ebp+12]
;       struct ipv4_fields *in    [ebp+8]
;
; driver.c documents the struct layout:
;
;   +0 version   +4 ihl    +8 dscp   +12 ecn   +16 total_length
;   +20 identification    +24 flags  +28 fragment_offset
;   +32 ttl      +36 protocol       +40 checksum
;   +44 src[0..3]                   +48 dst[0..3]
;
; You write twenty bytes into hdr. Every multi-byte field goes out
; big-endian: the high byte first. The fragment offset's top five bits share
; byte 6 with the three flag bits. Its bottom eight bits are byte 7.
;
; The checksum is your job too. Bytes 10-11 must read as zero while the
; checksum is computed. Write them as zero, call ip_checksum over the
; finished header, and store its result into the field. The struct's
; checksum member is read on the decode path only. Don't copy it here.
;
; Do not clobber ebx, esi, edi, or ebp. C assumes they survive your call.
; Return in eax (driver.c ignores it here, so returning 0 is fine).
;

; Windows C puts a leading underscore on every exported name. Linux C does
; not. The Makefile passes -d ELF_TYPE on Linux. This block then respells
; the names below to match. asm_io.inc does the same for _asm_main in the
; bootcamp blocks. Leave this block alone.
%ifdef ELF_TYPE
  %define _ip_checksum ip_checksum
  %define _encode_header encode_header
  section .note.GNU-stack noalloc noexec nowrite progbits
%endif

; Struct offsets and header constants.
F_DSCP      equ 8
F_ECN       equ 12
F_TOTLEN    equ 16
F_ID        equ 20
F_FLAGS     equ 24
F_FRAG      equ 28
F_TTL       equ 32
F_PROTO     equ 36
F_SRC       equ 44
F_DST       equ 48
IP_VER_IHL  equ 0x45            ; version 4, IHL 5(internet header length)
IP_HDR_LEN  equ 20

; Bit-field widths and positions inside the header bytes.
DSCP_MASK   equ 0x3F            ; DSCP is 6 bits
DSCP_SHIFT  equ 2               ; DSCP sits above the 2 ECN bits in byte 1
FLAGS_MASK  equ 0x07            ; flags are 3 bits
FLAGS_SHIFT equ 13              ; flags sit above the 13-bit fragment offset
FRAG_MASK   equ 0x1FFF          ; fragment offset is 13 bits

extern _ip_checksum

segment .text
        global  _encode_header
_encode_header:
        enter   0,0
        pusha

        mov     esi, [ebp + 8]          ; esi = struct ipv4_fields *in
        mov     edi, [ebp + 12]         ; edi = unsigned char *hdr

        ; byte 0: version 4, IHL 5
        mov     byte [edi], IP_VER_IHL

        ; byte 1: DSCP (6 bits) | ECN (2 bits)
        mov     eax, [esi + F_DSCP]
        and     eax, DSCP_MASK
        shl     eax, DSCP_SHIFT
        mov     ecx, [esi + F_ECN]
        and     ecx, 0x03
        or      eax, ecx
        mov     [edi + 1], al

        ; bytes 2-3: total length, big-endian
        mov     eax, [esi + F_TOTLEN]
        mov     [edi + 2], ah
        mov     [edi + 3], al

        ; bytes 4-5: identification, big-endian
        mov     eax, [esi + F_ID]
        mov     [edi + 4], ah
        mov     [edi + 5], al

        ; bytes 6-7: flags (3 bits) << 13 | fragment offset (13 bits)
        mov     eax, [esi + F_FLAGS]
        and     eax, FLAGS_MASK
        shl     eax, FLAGS_SHIFT
        mov     ecx, [esi + F_FRAG]
        and     ecx, FRAG_MASK
        or      eax, ecx
        mov     [edi + 6], ah
        mov     [edi + 7], al

        ; bytes 8-9: TTL, protocol
        mov     eax, [esi + F_TTL]
        mov     [edi + 8], al
        mov     eax, [esi + F_PROTO]
        mov     [edi + 9], al

        ; bytes 12-19: source and destination addresses, copied as-is
        mov     eax, [esi + F_SRC]
        mov     [edi + 12], eax
        mov     eax, [esi + F_DST]
        mov     [edi + 16], eax

        ; checksum last: bytes 10-11 zero while summing
        mov     word [edi + 10], 0
        push    dword IP_HDR_LEN
        push    edi                     ; edi = hdr, survives the call
        call    _ip_checksum
        add     esp, 8
        mov     [edi + 10], ah          ; big-endian: high byte first
        mov     [edi + 11], al

        popa
        mov     eax, 0
        leave
        ret
