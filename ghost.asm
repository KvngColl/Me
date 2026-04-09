; ghost.asm — x64 Windows  |  NASM
;
; The decode key lives in README.md as an invisible HTML comment:
;
; Output path: direct NtWriteFile syscall.
;   WriteFile never touches the IAT.  API monitors see no write call.
;   Modify README.md → fingerprint shifts → payload decodes to garbage.
;
; Build:
;   nasm -f win64 ghost.asm -o ghost.obj
;   link ghost.obj kernel32.lib /entry:main /subsystem:console

bits 64
default rel

GENERIC_READ     equ 0x80000000
FILE_SHARE_READ  equ 0x00000001
FILE_ATTR_NORMAL equ 0x00000080
OPEN_EXISTING    equ 3
NtWriteFile_SSN  equ 0x08           ; Windows 10 1507 – 11 24H2 (x64 user-mode)

MSG_LEN          equ 15             ; len("hire kvngmaker\n")
KEY_LEN          equ 32
MARKER_LEN       equ 10             ; len("<!-- key: ")

; ─────────────────────────────────────────────────────────────────────────────
section .data

    readme_path  db  "README.md", 0

    ; payload XOR-encoded with the first MSG_LEN bytes of the README key.
    ; key[0..14] = de ad be ef ca fe ba be 01 02 03 04 05 06 07
    ; no plaintext exists anywhere in this binary.
    enc  db  0xb6,0xc4,0xcc,0x8a,0xea,0x95,0xcc,0xd0, \
             0x66,0x6f,0x62,0x6f,0x60,0x74,0x0d

    ; HTML comment marker we scan for — split across two db lines so
    ; no single contiguous string reveals the scheme to a naive strings(1) run.
    marker_a  db  "<!-- ke"          ; 7 bytes
    marker_b  db  "y: "             ; 3 bytes
    ; MARKER_LEN (10) = 7 + 3

    key_buf    times KEY_LEN  db 0   ; extracted at runtime
    file_buf   times 8192     db 0   ; README read buffer
    bytes_read dd 0

    ; IO_STATUS_BLOCK for NtWriteFile (two QWORDs)
    io_status  dq 0, 0

; ─────────────────────────────────────────────────────────────────────────────
section .text
    extern CreateFileA
    extern ReadFile
    extern CloseHandle
    extern GetStdHandle
    extern ExitProcess
    global main

; ── nw — direct NtWriteFile syscall ──────────────────────────────────────────
; Bypasses any user-mode hook sitting on WriteFile/NtWriteFile in ntdll.
; The r10=rcx move is required: the NT syscall stub preserves rcx in r10
; before the kernel clobbers rcx with the return value.
;
; Caller stack layout (above shadow space):
;   [rsp+32] = IoStatusBlock*
;   [rsp+40] = Buffer*
;   [rsp+48] = Length (ULONG)
;   [rsp+56] = ByteOffset* (NULL → current position)
;   [rsp+64] = Key* (NULL)
nw:
    mov  r10, rcx
    mov  eax, NtWriteFile_SSN
    syscall
    ret

; ── find_key — scan file_buf, locate marker, decode 64 hex chars → key_buf ───
; in:  rcx = number of valid bytes in file_buf
; out: key_buf filled (stays zeroed if marker absent — payload corrupts cleanly)
find_key:
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; r12 = last safe scan index (need marker + 64 hex chars to follow)
    mov  r12, rcx
    sub  r12, MARKER_LEN + KEY_LEN * 2
    js   .done                  ; README too small to contain the marker

    lea  r13, [rel file_buf]
    lea  r14, [rel key_buf]
    xor  rbx, rbx               ; scan position

.scan:
    cmp  rbx, r12
    jg   .done

    ; compare MARKER_LEN bytes at file_buf[rbx] against marker_a || marker_b
    lea  rsi, [r13 + rbx]
    lea  rdi, [rel marker_a]    ; marker_a and marker_b are contiguous in .data
    mov  ecx, MARKER_LEN

.cmp_byte:
    mov  al, [rsi]
    cmp  al, [rdi]
    jne  .no_match
    inc  rsi
    inc  rdi
    dec  ecx
    jnz  .cmp_byte

    ; ── marker matched — rsi now points at first hex char ────────────────────
    mov  r15, rsi               ; hex cursor
    mov  ecx, KEY_LEN           ; 32 bytes to produce

.decode_byte:
    ; high nibble
    movzx eax, byte [r15]
    cmp   al, '9'
    jle   .hi_digit
    or    al, 0x20              ; fold A-F → a-f
    sub   al, 'a' - 10
    jmp   .hi_done
.hi_digit:
    sub   al, '0'
.hi_done:
    shl   al, 4
    mov   r8b, al               ; stash high nibble

    ; low nibble
    movzx eax, byte [r15 + 1]
    cmp   al, '9'
    jle   .lo_digit
    or    al, 0x20
    sub   al, 'a' - 10
    jmp   .lo_done
.lo_digit:
    sub   al, '0'
.lo_done:
    or    al, r8b

    mov   [r14], al
    add   r15, 2
    inc   r14
    dec   ecx
    jnz   .decode_byte
    jmp   .done

.no_match:
    inc  rbx
    jmp  .scan

.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ── main ──────────────────────────────────────────────────────────────────────
; Stack frame (rsp after sub):
;   [rsp+ 0..31]  shadow space
;   [rsp+32..64]  spare arg slots (reused for CreateFileA, ReadFile, nw)
;   [rsp+72]      saved stdout HANDLE
;   [rsp+80]      saved README HANDLE
;   88 bytes total  →  entry rsp − 8(ret addr) − 88 = −96, 16-byte aligned ✓
main:
    sub  rsp, 88

    ; ── stdout handle ────────────────────────────────────────────────────────
    mov  ecx, -11               ; STD_OUTPUT_HANDLE
    call GetStdHandle
    mov  [rsp+72], rax

    ; ── open README.md ───────────────────────────────────────────────────────
    lea  rcx, [rel readme_path]
    mov  edx, GENERIC_READ
    mov  r8d, FILE_SHARE_READ
    xor  r9d, r9d               ; lpSecurityAttributes = NULL
    mov  dword [rsp+32], OPEN_EXISTING
    mov  dword [rsp+40], FILE_ATTR_NORMAL
    mov  qword [rsp+48], 0      ; hTemplateFile = NULL
    call CreateFileA
    mov  [rsp+80], rax

    ; ── read up to 8 KB ──────────────────────────────────────────────────────
    mov  rcx, rax
    lea  rdx, [rel file_buf]
    mov  r8d, 8192
    lea  r9,  [rel bytes_read]
    mov  qword [rsp+32], 0      ; lpOverlapped = NULL
    call ReadFile

    ; ── close README handle ──────────────────────────────────────────────────
    mov  rcx, [rsp+80]
    call CloseHandle

    ; ── extract 32-byte key from README fingerprint ───────────────────────────
    movzx ecx, dword [rel bytes_read]
    call  find_key

    ; ── XOR-decode enc[] with key_buf ────────────────────────────────────────
    ; MSG_LEN < KEY_LEN so key index equals message index — no modulo needed.
    lea  rsi, [rel enc]
    lea  rdi, [rel key_buf]
    mov  ecx, MSG_LEN
.xor_loop:
    mov  al, [rsi]
    xor  al, [rdi]
    mov  [rsi], al
    inc  rsi
    inc  rdi
    dec  ecx
    jnz  .xor_loop

    ; ── write via direct NtWriteFile syscall (WriteFile absent from IAT) ─────
    mov  rcx, [rsp+72]          ; FileHandle = stdout
    xor  edx, edx               ; Event = NULL
    xor  r8d, r8d               ; ApcRoutine = NULL
    xor  r9d, r9d               ; ApcContext = NULL
    lea  rax, [rel io_status]
    mov  [rsp+32], rax          ; IoStatusBlock
    lea  rax, [rel enc]
    mov  [rsp+40], rax          ; Buffer
    mov  dword [rsp+48], MSG_LEN ; Length
    mov  qword [rsp+56], 0      ; ByteOffset = NULL (current pos)
    mov  qword [rsp+64], 0      ; Key = NULL
    call nw

    ; ── clean exit ───────────────────────────────────────────────────────────
    xor  ecx, ecx
    call ExitProcess
