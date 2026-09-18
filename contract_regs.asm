;
; contract_regs.asm - call each routine with sentinel registers.
;
; The stdout comparison cannot see whether a routine leaves a callee-saved
; register changed. C calls these routines and assumes that ebx, esi, edi,
; and ebp survive, and that esp returns to where the call left it. A
; routine that breaks one of those promises produces failures far from the
; cause, in code the student did not write.
;
; Each function below loads a sentinel into ebx, esi, and edi. It records
; its own ebp and the esp the callee must return with. It calls the routine
; under test and returns a bitmask:
;
;   bit 0  ebx changed
;   bit 1  esi changed
;   bit 2  edi changed
;   bit 3  esp is not where the call left it
;   bit 4  ebp changed
;
; Zero means every one of them survived. The starter provides this file. Do
; not modify it.
;
; The wrapper keeps its own ebp in memory, not on the stack. After the call
; it trusts no register. It compares ebp and esp against the saved copies,
; then reloads both from the saved copies before it touches the stack. A
; routine that changes ebp, or returns with esp off by eight, is therefore
; reported and the wrapper still returns to C.
;
; Two failures the wrapper cannot report. A routine that changes ebp and
; then runs leave crashes inside leave, before it returns here. A routine
; that leaves an extra value on the stack returns to that value instead of
; to this code. Both crash the contract test, and run_tests.sh reports the
; crash as a failed contract pass.
;

; Windows C puts a leading underscore on every exported name. Linux C does
; not. The Makefile passes -d ELF_TYPE on Linux. This block then respells
; the names below to match. asm_io.inc does the same for _asm_main in the
; bootcamp blocks.
%ifdef ELF_TYPE
  %define _decode_header decode_header
  %define _encode_header encode_header
  %define _ip_checksum ip_checksum
  %define _check_decode_registers check_decode_registers
  %define _check_encode_registers check_encode_registers
  %define _check_checksum_registers check_checksum_registers
  section .note.GNU-stack noalloc noexec nowrite progbits
%endif

extern _decode_header
extern _encode_header
extern _ip_checksum

%define SENTINEL_EBX 0x11111111
%define SENTINEL_ESI 0x22222222
%define SENTINEL_EDI 0x33333333

segment .bss
saved_ebp       resd    1               ; the wrapper's own frame pointer
expected_esp    resd    1               ; esp as the callee must return it

segment .text

;
; call_and_verdict ROUTINE - the body every wrapper shares. It expects the
; sentinels loaded and the two arguments still at [ebp+8] and [ebp+12]. It
; leaves the bitmask in eax, ebp restored, and esp at the point right after
; the three pushes in the wrapper's prologue.
;
%macro call_and_verdict 1
        mov     [saved_ebp], ebp
        push    dword [ebp+12]          ; second argument
        push    dword [ebp+8]           ; first argument
        mov     [expected_esp], esp     ; the call pushes and ret pops, so this is the target
        call    %1

        ; Build the verdict without trusting any register the callee may
        ; have changed. Memory holds the two values that matter.
        xor     eax, eax
        cmp     ebx, SENTINEL_EBX
        je      %%ebx_ok
        or      eax, 1
%%ebx_ok:
        cmp     esi, SENTINEL_ESI
        je      %%esi_ok
        or      eax, 2
%%esi_ok:
        cmp     edi, SENTINEL_EDI
        je      %%edi_ok
        or      eax, 4
%%edi_ok:
        cmp     esp, [expected_esp]
        je      %%esp_ok
        or      eax, 8
%%esp_ok:
        cmp     ebp, [saved_ebp]
        je      %%ebp_ok
        or      eax, 16
%%ebp_ok:
        ; Recover the frame and the stack pointer from memory. The three
        ; callee-saved pushes in the prologue sit right below the frame.
        mov     ebp, [saved_ebp]
        lea     esp, [ebp-12]
%endmacro

; int check_decode_registers(unsigned char *hdr, struct ipv4_fields *out)
        global  _check_decode_registers
_check_decode_registers:
        enter   0,0
        push    ebx
        push    esi
        push    edi

        mov     ebx, SENTINEL_EBX
        mov     esi, SENTINEL_ESI
        mov     edi, SENTINEL_EDI
        call_and_verdict _decode_header

        pop     edi
        pop     esi
        pop     ebx
        leave
        ret

; int check_encode_registers(struct ipv4_fields *in, unsigned char *hdr)
        global  _check_encode_registers
_check_encode_registers:
        enter   0,0
        push    ebx
        push    esi
        push    edi

        mov     ebx, SENTINEL_EBX
        mov     esi, SENTINEL_ESI
        mov     edi, SENTINEL_EDI
        call_and_verdict _encode_header

        pop     edi
        pop     esi
        pop     ebx
        leave
        ret

; int check_checksum_registers(unsigned char *hdr, int len)
        global  _check_checksum_registers
_check_checksum_registers:
        enter   0,0
        push    ebx
        push    esi
        push    edi

        mov     ebx, SENTINEL_EBX
        mov     esi, SENTINEL_ESI
        mov     edi, SENTINEL_EDI
        call_and_verdict _ip_checksum

        pop     edi
        pop     esi
        pop     ebx
        leave
        ret
