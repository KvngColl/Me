/* jit.c — single-file x64 JIT emitter + loader  (Windows, MSVC / GCC / clang)
 *
 * Hand-encodes x64 machine instructions at runtime using raw REX / ModRM / SIB
 * rules.  No assembler.  No LLVM.  No external JIT library.
 *
 * Two live-synthesised functions are built, shown, and executed:
 *
 *   add_fn(a, b) → a + b          pure LEA arithmetic, no imports
 *   msg_fn()     → MessageBoxA    API pointer embedded as imm64 operand
 *
 * Build:
 *   MSVC :  cl  /O2 /W4  jit.c
 *   GCC  :  gcc -O2 -Wall -o jit jit.c
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* ── register IDs (encoding order matches Intel manual) ──────────────────── */
typedef enum {
    RAX=0, RCX=1, RDX=2, RBX=3, RSP=4, RBP=5, RSI=6, RDI=7,
    R8=8,  R9=9,  R10=10, R11=11, R12=12, R13=13, R14=14, R15=15
} Reg;

/* ── emit buffer ─────────────────────────────────────────────────────────── */
#define BUF_MAX 256
typedef struct { uint8_t b[BUF_MAX]; size_t n; } Buf;

static void eb (Buf *e, uint8_t  v) { if (e->n < BUF_MAX) e->b[e->n++] = v; }
static void e32(Buf *e, uint32_t v) {
    eb(e,(uint8_t)v); eb(e,(uint8_t)(v>>8));
    eb(e,(uint8_t)(v>>16)); eb(e,(uint8_t)(v>>24));
}
static void e64(Buf *e, uint64_t v) { e32(e,(uint32_t)v); e32(e,(uint32_t)(v>>32)); }

/* ── instruction encoders ────────────────────────────────────────────────── */

/*  MOV r64, imm64                   REX.W [REX.B]  B8+rd  imm64
 *  rax–rdi → REX=48   r8–r15 → REX=49 (sets REX.B; low 3 bits of rd stay 0-7) */
static void mov_r_imm64(Buf *e, Reg r, uint64_t v) {
    eb(e, 0x48 | (r >= R8 ? 1 : 0));
    eb(e, 0xB8 | (r & 7));
    e64(e, v);
}

/*  XOR r32, r32   (implicitly zeros upper 32 bits → full 64-bit zero)
 *  Opcode 33 /r, ModRM = 11_r_r
 *  r8–r15 needs REX.R | REX.B = 0x45 */
static void xor_r32(Buf *e, Reg r) {
    uint8_t lo = r & 7;
    if (r >= R8) eb(e, 0x45);
    eb(e, 0x33);
    eb(e, (uint8_t)(0xC0 | (lo << 3) | lo));
}

/*  SUB RSP, imm8     48 83 EC imm8 */
static void sub_rsp_i8(Buf *e, uint8_t i) {
    eb(e,0x48); eb(e,0x83); eb(e,0xEC); eb(e,i);
}

/*  ADD RSP, imm8     48 83 C4 imm8 */
static void add_rsp_i8(Buf *e, uint8_t i) {
    eb(e,0x48); eb(e,0x83); eb(e,0xC4); eb(e,i);
}

/*  CALL r64     FF /2  (ModRM = 11_010_r)
 *  r8–r15 prefix REX.B = 0x41 */
static void call_r(Buf *e, Reg r) {
    if (r >= R8) eb(e, 0x41);
    eb(e, 0xFF);
    eb(e, (uint8_t)(0xD0 | (r & 7)));
}

/*  LEA RAX, [RCX + RDX]   48 8D 04 11
 *  ModRM(00,RAX,SIB=0x04)  SIB(×1,RDX,RCX=0x11) */
static void lea_rax_rcx_rdx(Buf *e) {
    eb(e,0x48); eb(e,0x8D); eb(e,0x04); eb(e,0x11);
}

/*  RET */
static void ret(Buf *e) { eb(e, 0xC3); }

/* ── hexdump ─────────────────────────────────────────────────────────────── */
static void hexdump(const char *tag, const Buf *b) {
    printf("  [emit] %s  (%zu bytes)\n  ", tag, b->n);
    for (size_t i = 0; i < b->n; i++) {
        printf("%02x ", b->b[i]);
        if ((i+1) % 16 == 0 && i+1 < b->n) printf("\n  ");
    }
    puts("\n");
}

/* ── RWX page alloc + copy ───────────────────────────────────────────────── */
static void *alloc_exec(const Buf *src) {
    void *p = VirtualAlloc(NULL, src->n,
                           MEM_COMMIT | MEM_RESERVE,
                           PAGE_EXECUTE_READWRITE);
    if (p) memcpy(p, src->b, src->n);
    return p;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  DEMO 1
 *
 *  Windows x64: a → rcx, b → rdx, return → rax
 *
 *    lea  rax, [rcx+rdx]   ; 48 8D 04 11
 *    ret                   ; C3
 */
typedef long long (*AddFn)(long long, long long);

static AddFn build_add(void) {
    Buf e = {0};
    lea_rax_rcx_rdx(&e);
    ret(&e);
    hexdump("add_fn", &e);
    return (AddFn)alloc_exec(&e);
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  DEMO 2 
 *
 *  MessageBoxA(hwnd, text, caption, type) — args in rcx rdx r8 r9
 *  API pointer baked in as a literal imm64; no import table entry.
 *
 *    sub  rsp, 40         ; 48 83 EC 28   shadow(32)+align(8)
 *    xor  ecx, ecx        ; 33 C9         hwnd = NULL
 *    mov  rdx, <text>     ; 48 BA …
 *    mov  r8,  <caption>  ; 49 B8 …
 *    xor  r9d, r9d        ; 45 33 C9      uType = 0
 *    mov  rax, <fn>       ; 48 B8 …
 *    call rax             ; FF D0
 *    add  rsp, 40         ; 48 83 C4 28
 *    xor  eax, eax        ; 33 C0
 *    ret                  ; C3
 */
typedef void (*MsgFn)(void);

static const char msg_text[]    = "hire kvngmaker";
static const char msg_caption[] = "ghost.exe";

static MsgFn build_msg(void) {
    HMODULE u32 = LoadLibraryA("user32.dll");
    if (!u32) { fputs("[-] user32.dll load failed\n", stderr); return NULL; }

    void *mb = (void *)(uintptr_t)GetProcAddress(u32, "MessageBoxA");
    if (!mb) { fputs("[-] MessageBoxA not found\n", stderr); return NULL; }

    Buf e = {0};
    sub_rsp_i8(&e, 40);
    xor_r32  (&e, RCX);
    mov_r_imm64(&e, RDX, (uint64_t)(uintptr_t)msg_text);
    mov_r_imm64(&e, R8,  (uint64_t)(uintptr_t)msg_caption);
    xor_r32  (&e, R9);
    mov_r_imm64(&e, RAX, (uint64_t)(uintptr_t)mb);
    call_r   (&e, RAX);
    add_rsp_i8(&e, 40);
    xor_r32  (&e, RAX);
    ret      (&e);

    hexdump("msg_fn", &e);
    return (MsgFn)alloc_exec(&e);
}

/* ─────────────────────────────────────────────────────────────────────────── */
int main(void) {
    puts("=== x64 JIT emitter ===\n");

    AddFn add = build_add();
    if (add) {
        long long r = add(21LL, 21LL);
        printf("[+] add_fn(21, 21) = %lld\n\n", r);
        VirtualFree((LPVOID)add, 0, MEM_RELEASE);
    }

    MsgFn msg = build_msg();
    if (msg) {
        msg();
        VirtualFree((LPVOID)msg, 0, MEM_RELEASE);
    }

    return 0;
}
