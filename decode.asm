;
; decode.asm - extract every field from a 20-byte IPv4 header.
;
; This is your starting point. It assembles and links as-is, so the build
; works before you write any code. Right now it stores nothing, so renpkt
; prints the zeros driver.c put in the struct. Your job is to replace that
; with the extraction described below.
;
; The contract, from driver.c:
;
;       struct ipv4_fields *out   [ebp+12]
;       unsigned char *hdr        [ebp+8]
;
; hdr points at twenty bytes in network byte order. out points at the struct
; documented in driver.c. Its offsets are:
;
;   +0 version   +4 ihl    +8 dscp   +12 ecn   +16 total_length
;   +20 identification    +24 flags  +28 fragment_offset
;   +32 ttl      +36 protocol       +40 checksum
;   +44 src[0..3]                   +48 dst[0..3]
;
; Every int member is 4 bytes, so a plain 32-bit store fills one. The
; addresses are four single-byte stores each.
;
; Do not clobber ebx, esi, edi, or ebp. C assumes they survive your call.
; Return in eax (driver.c ignores it here, so returning 0 is fine).
;

; 4 bits to mask
%define IHL_MASK        0x0F
; 2 bits to mask 0000 0011
%define ECN_MASK        0x03
; 3 bits to mask 0000 0111
%define FLAG_MASK       0x07
; 13 bits to mask 0001 1111 1111 1111
%define FRAG_MASK       0x1FFF
; 8 bits to mask 1111 1111
%define TTL_MASK        0xFF
; 8 bits to mask 1111 1111
%define PROTO_MASK      0xFF

%define VER_SHIFT 4
%define DSCP_SHIFT 2
%define FLAG_SHIFT 13

%macro combine_endian 3
        movzx   %3, byte [%1 + %2] ; high byte
        shl     %3, 8
        movzx   ebx, byte [%1 + %2 + 1] ; low byte
        or      %3, ebx         ; NOTE: clobbers ebx as scratch
%endmacro

; Windows C puts a leading underscore on every exported name. Linux C does
; not. The Makefile passes -d ELF_TYPE on Linux. This block then respells
; the names below to match. asm_io.inc does the same for _asm_main in the
; bootcamp blocks. Leave this block alone.
%ifdef ELF_TYPE
  %define _decode_header decode_header
  section .note.GNU-stack noalloc noexec nowrite progbits
%endif

segment .text
        global  _decode_header
_decode_header:
        enter   0,0
        pusha

        ;
        ; TODO: read the header and fill the struct.
        ;
        ; The field-by-field layout is the table in the manual. The notes
        ; that matter before you start:
        ;
        ;   * Every multi-byte field is big-endian, so load it byte by byte
        ;     and recombine. A single 16-bit load gives you the bytes
        ;     reversed.
        ;   * The fragment offset straddles a byte boundary. Its top five
        ;     bits live in byte 6 and its bottom eight in byte 7. Combine
        ;     both bytes into one word first, then shift and mask.
        ;   * The flags are the top three bits of the same word.
        ;   * Read and store the checksum field like any other field.
        ;     ip_checksum computes the VALID line separately.
        ;   * src and dst are four single-byte stores each. No shifting.
        ;
        ; Nothing here reads the file or prints. This routine only fills
        ; the struct, and driver.c does the rest.
        ;

        ; in 20-byte IPV4 header
        mov     esi, [ebp+8] 
        mov     edi, [ebp+12]

        ; decode hdr for version and IHL
        movzx   eax, byte [esi]         ; eax = byte 0
        mov     ebx, eax
        shr     ebx, VER_SHIFT          ; ebx = version (high nibble)
        and     eax, IHL_MASK           ; eax = IHL (low nibble)

        ; fill the struct
        mov     [edi+0], ebx
        mov     [edi+4], eax

        ; byte 1 fields DSCP & ECN
        movzx   eax, byte [esi + 1]     ; eax = byte 1

        mov     ebx, eax        ; ebx = DSCP (top 6 bits)
        shr     ebx, DSCP_SHIFT
        mov     [edi + 8], ebx

        and     eax, ECN_MASK   ; eax = ECN (bottom 2 bits)
        mov     [edi + 12], eax

        ; byte 2-3
        combine_endian  esi, 2, eax     ; esi holds address pointer, 2 is starting byte, put in eax
        mov     [edi + 16], eax         ; total length

        ; byte 4-5
        combine_endian  esi, 4, eax
        mov     [edi + 20], eax         ; identification

        ; byte 6 flags
        combine_endian  esi, 6, eax

        mov     ebx, eax                ; eax needed for fragment offset
        shr     ebx, FLAG_SHIFT                 ; top 3 bits gets shifted down
        and     ebx, FLAG_MASK

        mov     [edi + 24], ebx

        ; byte 6-7 fragment offset
        and     eax, FRAG_MASK          ; mask the low 13 bits
        mov     [edi + 28], eax

        ; byte 8 TTL
        movzx   eax, byte [esi + 8]
        and     eax, TTL_MASK           ; mask 8 bits

        mov     [edi + 32], eax

        ; byte 9 protocol
        movzx   eax, byte [esi + 9]
        and     eax, PROTO_MASK         ; mask 8 bits

        mov     [edi + 36], eax

        ; byte 10-11 header-checksum
        combine_endian  esi, 10, eax

        mov     [edi + 40], eax

        ; byte 12-15 source address
        mov     al, byte [esi + 12]
        mov     [edi + 44], al

        mov     al, byte [esi + 13]
        mov     [edi + 45], al

        mov     al, byte [esi + 14]
        mov     [edi + 46], al

        mov     al, byte [esi + 15]
        mov     [edi + 47], al

        ; byte 16-19 destination address
        mov     al, byte [esi + 16]
        mov     [edi + 48], al

        mov     al, byte [esi + 17]
        mov     [edi + 49], al

        mov     al, byte [esi + 18]
        mov     [edi + 50], al

        mov     al, byte [esi + 19]
        mov     [edi + 51], al

        popa
        mov     eax, 0
        leave
        ret
