#!/usr/bin/env python3
"""
ReverseLab VM (Phase 4)

Single-file reversing showcase:
- Encrypted bytecode image (at-rest obfuscation)
- Runtime decode windows (only small slices are decrypted on demand)
- Integrity gate opcode with image checksum verification
- Decoy instruction stream reachable under tampered control flow
- Flattened VM dispatcher and opaque predicates
- Anti-debug timing/trace probe
- Dead block islands that require crafted predicates to activate
- Disassembler, emulator, and inverse solver

Usage:
  python reverse_lab.py --mode disasm
  python reverse_lab.py --mode solve
  python reverse_lab.py --mode check --key ghostkey
  python reverse_lab.py --mode all
"""

from __future__ import annotations

import argparse
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

# Opcodes
OP_LOAD_IDX = 0x10     # LOAD_IDX <idx>
OP_XOR_IMM = 0x20      # XOR      <imm8>
OP_ROL_IMM = 0x30      # ROL      <imm8>
OP_ADD_IMM = 0x40      # ADD      <imm8>
OP_CMP_IMM = 0x50      # CMP      <imm8>
OP_JNE_FAIL = 0x60     # JNE_FAIL
OP_RET_OK = 0x70       # RET_OK
OP_RET_FAIL = 0x71     # RET_FAIL
OP_DEAD_ISLAND = 0x90  # DEAD_ISLAND <token>
OP_GUARD_DECOY = 0xA0  # GUARD_DECOY <lo> <hi>
OP_INTEGRITY = 0xA1    # INTEGRITY_CHECK

KEY_LEN = 8
WIN = 16  # runtime decode window size

# Challenge constants (the clear key is not stored in source).
XOR_K = [0x13, 0x37, 0xC0, 0x55, 0x9A, 0x21, 0x7F, 0x42]
ROL_K = [1, 3, 5, 2, 7, 4, 6, 3]
ADD_K = [0x11, 0x22, 0x33, 0x44, 0x10, 0x20, 0x30, 0x40]
POST_X = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xAB, 0xBC, 0xCD]
TARGET = [0x53, 0xA7, 0xE4, 0x01, 0x69, 0x6F, 0x0A, 0xD4]
DEAD_TOKENS = [0x3A, 0x11, 0x7E, 0x29, 0x53, 0x64, 0x90, 0x2F]


@dataclass
class BytecodeImage:
    encrypted: List[int]
    seed: int
    expected_hash: int


@dataclass
class VMResult:
    ok: bool
    fail_index: int
    reason: str = ""


def rol8(v: int, r: int) -> int:
    r &= 7
    return ((v << r) | (v >> (8 - r))) & 0xFF


def ror8(v: int, r: int) -> int:
    r &= 7
    return ((v >> r) | (v << (8 - r))) & 0xFF


def opaque_true(x: int) -> bool:
    # n(n+1) is always even, but this looks noisy in static traces.
    return (((x * x + x) ^ 0xAA) & 1) == (0xAA & 1)


def crafted_dead_predicate(acc: int, idx: int, token: int) -> bool:
    # Intentionally rare condition for dead island entry.
    return (((acc ^ (idx * 13) ^ token) * 7 + 3) & 0xFF) == 0xA5


def image_hash(enc: List[int], seed: int) -> int:
    # FNV-1a style 32-bit hash over encrypted image + seed.
    h = 0x811C9DC5 ^ (seed & 0xFFFFFFFF)
    for i, b in enumerate(enc):
        h ^= (b + ((i * 131) & 0xFF)) & 0xFFFFFFFF
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def anti_debug_probe() -> List[str]:
    hits: List[str] = []

    if sys.gettrace() is not None:
        hits.append("active trace/debug hook")

    # Timing jitter probe: conservative threshold to reduce false positives.
    t0 = time.perf_counter_ns()
    z = 0
    for i in range(250_000):
        z = ((z + i) ^ 0x5A) & 0xFFFFFFFF
    dt_ns = time.perf_counter_ns() - t0
    if dt_ns > 170_000_000:
        hits.append("timing anomaly in tight loop")

    if z == -1:  # opaque dead branch
        hits.append("impossible state")

    return hits


def build_plain_bytecode() -> List[int]:
    bc: List[int] = [OP_INTEGRITY]
    guard_patch_sites: List[int] = []

    for i in range(KEY_LEN):
        bc += [OP_LOAD_IDX, i]
        bc += [OP_XOR_IMM, XOR_K[i]]
        bc += [OP_ROL_IMM, ROL_K[i]]
        bc += [OP_ADD_IMM, ADD_K[i]]
        bc += [OP_XOR_IMM, POST_X[i]]
        bc += [OP_CMP_IMM, TARGET[i]]
        bc += [OP_JNE_FAIL]
        # If control flow is tampered (e.g., patched JNE), redirect into decoy stream.
        guard_patch_sites.append(len(bc) + 1)
        bc += [OP_GUARD_DECOY, 0x00, 0x00]
        # Dead island between blocks, guarded by crafted predicate.
        bc += [OP_DEAD_ISLAND, DEAD_TOKENS[i]]

    bc += [OP_RET_OK, OP_RET_FAIL]

    # Decoy block: believable-looking but intentionally wrong path.
    decoy_start = len(bc)
    bc += [
        OP_LOAD_IDX, 0,
        OP_XOR_IMM, 0xDE,
        OP_CMP_IMM, 0xAD,
        OP_JNE_FAIL,
        OP_LOAD_IDX, 1,
        OP_XOR_IMM, 0xBE,
        OP_CMP_IMM, 0xEF,
        OP_JNE_FAIL,
        OP_RET_FAIL,
    ]

    lo = decoy_start & 0xFF
    hi = (decoy_start >> 8) & 0xFF
    for site in guard_patch_sites:
        bc[site] = lo
        bc[site + 1] = hi

    return bc


def stream_key_at(pos: int, seed: int) -> int:
    # Tiny position-dependent stream generator.
    x = (seed ^ (pos * 0x45D9F3B)) & 0xFFFFFFFF
    x ^= (x >> 16)
    x = (x * 0x45D9F3B) & 0xFFFFFFFF
    x ^= (x >> 16)
    return x & 0xFF


def encrypt_bytecode(plain: List[int], seed: int) -> BytecodeImage:
    enc = [(b ^ stream_key_at(i, seed)) & 0xFF for i, b in enumerate(plain)]
    return BytecodeImage(enc, seed, image_hash(enc, seed))


def decode_window(img: BytecodeImage, start: int, size: int) -> List[int]:
    end = min(len(img.encrypted), start + size)
    out: List[int] = []
    for i in range(start, end):
        out.append((img.encrypted[i] ^ stream_key_at(i, img.seed)) & 0xFF)
    return out


def decode_all(img: BytecodeImage) -> List[int]:
    return decode_window(img, 0, len(img.encrypted))


def read_byte_runtime(img: BytecodeImage, ip: int, cache: Dict[str, object]) -> Optional[int]:
    if ip < 0 or ip >= len(img.encrypted):
        return None

    w_start = int(cache.get("w_start", -1))
    w_data = cache.get("w_data")
    if not isinstance(w_data, list):
        w_data = []

    if not (w_start <= ip < w_start + len(w_data)):
        new_start = ip - (ip % WIN)
        w_data = decode_window(img, new_start, WIN)
        cache["w_start"] = new_start
        cache["w_data"] = w_data
        w_start = new_start

    return int(w_data[ip - w_start])


def emulate(img: BytecodeImage, key: bytes, strict_anti_debug: bool = False) -> VMResult:
    if len(key) != KEY_LEN:
        return VMResult(False, -1, "invalid key length")

    anti_hits = anti_debug_probe()
    if strict_anti_debug and anti_hits:
        return VMResult(False, -2, "anti-debug trigger: " + ", ".join(anti_hits))

    runtime_hash = image_hash(img.encrypted, img.seed)
    image_ok = runtime_hash == img.expected_hash
    if strict_anti_debug and not image_ok:
        return VMResult(False, -3, "integrity mismatch")

    ip = 0
    acc = 0
    last_idx = -1
    cmp_fail = False
    integrity_ok = image_ok

    state = 0  # flattened state machine: 0=FETCH, 1=EXEC, 2=HALT
    op = 0
    cache: Dict[str, object] = {"w_start": -1, "w_data": []}

    def rb() -> Optional[int]:
        nonlocal ip
        b = read_byte_runtime(img, ip, cache)
        if b is None:
            return None
        ip += 1
        return b

    def fetch() -> None:
        nonlocal op, state
        b = read_byte_runtime(img, ip, cache)
        if b is None:
            state = 2
            return

        # Opaque branch: both paths fetch equivalent data.
        if opaque_true(ip ^ acc):
            op_local = rb()
        else:
            op_local = rb()

        if op_local is None:
            state = 2
            return
        op = op_local
        state = 1

    def exec_op() -> Optional[VMResult]:
        nonlocal acc, last_idx, cmp_fail, state, integrity_ok, ip

        if op == OP_INTEGRITY:
            integrity_ok = image_hash(img.encrypted, img.seed) == img.expected_hash
            state = 0
            return None

        if op == OP_LOAD_IDX:
            idx = rb()
            if idx is None:
                return VMResult(False, last_idx, "truncated bytecode")
            last_idx = idx
            acc = key[idx]
            state = 0
            return None

        if op == OP_XOR_IMM:
            imm = rb()
            if imm is None:
                return VMResult(False, last_idx, "truncated bytecode")
            acc ^= imm
            state = 0
            return None

        if op == OP_ROL_IMM:
            imm = rb()
            if imm is None:
                return VMResult(False, last_idx, "truncated bytecode")
            acc = rol8(acc, imm)
            state = 0
            return None

        if op == OP_ADD_IMM:
            imm = rb()
            if imm is None:
                return VMResult(False, last_idx, "truncated bytecode")
            acc = (acc + imm) & 0xFF
            state = 0
            return None

        if op == OP_CMP_IMM:
            imm = rb()
            if imm is None:
                return VMResult(False, last_idx, "truncated bytecode")
            cmp_fail = acc != imm
            state = 0
            return None

        if op == OP_JNE_FAIL:
            if cmp_fail:
                return VMResult(False, last_idx, "cmp mismatch")
            state = 0
            return None

        if op == OP_GUARD_DECOY:
            lo = rb()
            hi = rb()
            if lo is None or hi is None:
                return VMResult(False, last_idx, "truncated guard")
            target = (hi << 8) | lo
            if cmp_fail or not integrity_ok:
                ip = target
                cmp_fail = False
            state = 0
            return None

        if op == OP_DEAD_ISLAND:
            token = rb()
            if token is None:
                return VMResult(False, last_idx, "truncated dead island")
            if crafted_dead_predicate(acc, max(last_idx, 0), token):
                # Dead island payload: intentionally useless arithmetic noise.
                acc = rol8((acc ^ token) + 0x39, 3)
                acc ^= 0x5C
            state = 0
            return None

        if op == OP_RET_OK:
            return VMResult(True, -1, "ok")

        if op == OP_RET_FAIL:
            return VMResult(False, last_idx, "ret fail")

        return VMResult(False, last_idx, f"unknown opcode 0x{op:02x}")

    while state != 2:
        if state == 0:
            fetch()
            continue

        out = exec_op()
        if out is not None:
            if anti_hits and out.ok:
                return VMResult(True, out.fail_index, out.reason + " | anti-debug hints: " + ", ".join(anti_hits))
            return out

    return VMResult(False, last_idx, "eof")


def disasm(plain: List[int]) -> str:
    out: List[str] = []
    ip = 0
    while ip < len(plain):
        op = plain[ip]
        base = f"{ip:04x}: "
        ip += 1

        if op == OP_LOAD_IDX:
            idx = plain[ip]
            ip += 1
            out.append(f"{base}LOAD_IDX     key[{idx}]")
        elif op == OP_INTEGRITY:
            out.append(f"{base}INTEGRITY")
        elif op == OP_XOR_IMM:
            imm = plain[ip]
            ip += 1
            out.append(f"{base}XOR          0x{imm:02x}")
        elif op == OP_ROL_IMM:
            imm = plain[ip]
            ip += 1
            out.append(f"{base}ROL          {imm}")
        elif op == OP_ADD_IMM:
            imm = plain[ip]
            ip += 1
            out.append(f"{base}ADD          0x{imm:02x}")
        elif op == OP_CMP_IMM:
            imm = plain[ip]
            ip += 1
            out.append(f"{base}CMP          0x{imm:02x}")
        elif op == OP_JNE_FAIL:
            out.append(f"{base}JNE_FAIL")
        elif op == OP_GUARD_DECOY:
            lo = plain[ip]
            hi = plain[ip + 1]
            ip += 2
            out.append(f"{base}GUARD_DECOY 0x{((hi << 8) | lo):04x}")
        elif op == OP_DEAD_ISLAND:
            tok = plain[ip]
            ip += 1
            out.append(f"{base}DEAD_ISLAND  0x{tok:02x}")
        elif op == OP_RET_OK:
            out.append(f"{base}RET_OK")
        elif op == OP_RET_FAIL:
            out.append(f"{base}RET_FAIL")
        else:
            out.append(f"{base}DB           0x{op:02x}")
    return "\n".join(out)


def recover_key_from_plain(plain: List[int]) -> bytes:
    # Recover per-byte inverse from instruction blocks:
    #   LOAD_IDX -> XOR -> ROL -> ADD -> XOR -> CMP -> JNE_FAIL -> DEAD_ISLAND
    recovered = [0] * KEY_LEN

    ip = 0

    if ip < len(plain) and plain[ip] == OP_INTEGRITY:
        ip += 1

    while ip < len(plain):
        op = plain[ip]
        if op == OP_RET_OK:
            break

        if op != OP_LOAD_IDX:
            raise ValueError(f"Unexpected opcode 0x{op:02x} at {ip:04x}")

        idx = plain[ip + 1]
        if plain[ip + 2] != OP_XOR_IMM:
            raise ValueError("Expected XOR_IMM")
        x1 = plain[ip + 3]

        if plain[ip + 4] != OP_ROL_IMM:
            raise ValueError("Expected ROL_IMM")
        r = plain[ip + 5]

        if plain[ip + 6] != OP_ADD_IMM:
            raise ValueError("Expected ADD_IMM")
        add_k = plain[ip + 7]

        if plain[ip + 8] != OP_XOR_IMM:
            raise ValueError("Expected post XOR_IMM")
        x2 = plain[ip + 9]

        if plain[ip + 10] != OP_CMP_IMM:
            raise ValueError("Expected CMP_IMM")
        target = plain[ip + 11]

        if plain[ip + 12] != OP_JNE_FAIL:
            raise ValueError("Expected JNE_FAIL")
        if plain[ip + 13] != OP_GUARD_DECOY:
            raise ValueError("Expected GUARD_DECOY")
        if plain[ip + 16] != OP_DEAD_ISLAND:
            raise ValueError("Expected DEAD_ISLAND")

        # Inverse:
        # target = (((in ^ x1) rol r) + add_k) ^ x2
        # => in = ror(((target ^ x2) - add_k), r) ^ x1
        v = target ^ x2
        v = (v - add_k) & 0xFF
        v = ror8(v, r)
        v ^= x1
        recovered[idx] = v

        ip += 18

    return bytes(recovered)


def printable(bs: bytes) -> bool:
    return all(32 <= b <= 126 for b in bs)


def build_image() -> BytecodeImage:
    plain = build_plain_bytecode()
    # Seed intentionally static so challenge remains deterministic.
    return encrypt_bytecode(plain, seed=0x5A17C3E9)


def run_all() -> int:
    img = build_image()
    plain = decode_all(img)

    print("== Encrypted Bytecode Snapshot ==")
    print("enc[0:32] =", " ".join(f"{b:02x}" for b in img.encrypted[:32]))
    print("expected_hash=0x%08x" % img.expected_hash)
    print(" runtime_hash=0x%08x" % image_hash(img.encrypted, img.seed))

    print("\n== Bytecode Disassembly ==")
    print(disasm(plain))

    hits = anti_debug_probe()
    print("\n== Anti-Debug Probe ==")
    if hits:
        print("Signals:", "; ".join(hits))
    else:
        print("Signals: none")

    print("\n== Solver ==")
    key = recover_key_from_plain(plain)
    print("Recovered key bytes:", " ".join(f"{b:02x}" for b in key))
    print("Recovered key text :", key.decode("ascii", "replace"))

    print("\n== Verification ==")
    res = emulate(img, key)
    print("Valid:", res.ok)
    print("Reason:", res.reason)
    return 0 if res.ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Advanced reversing mini-lab: encrypted VM + disasm + solver")
    parser.add_argument("--mode", choices=["disasm", "solve", "check", "all"], default="all")
    parser.add_argument("--key", default="", help="Candidate key for --mode check")
    parser.add_argument("--strict-anti-debug", action="store_true", help="Fail validation if anti-debug probe detects tracing/timing anomalies")
    args = parser.parse_args()

    img = build_image()
    plain = decode_all(img)

    if args.mode == "disasm":
        print(disasm(plain))
        return 0

    if args.mode == "solve":
        key = recover_key_from_plain(plain)
        print(key.decode("ascii", "replace") if printable(key) else key.hex())
        return 0

    if args.mode == "check":
        key = args.key.encode("utf-8", "ignore")
        res = emulate(img, key, strict_anti_debug=args.strict_anti_debug)
        if res.ok:
            print("VALID")
            if res.reason:
                print("INFO:", res.reason)
            return 0
        print(f"INVALID (failed byte index: {res.fail_index})")
        if res.reason:
            print("REASON:", res.reason)
        return 1

    return run_all()


if __name__ == "__main__":
    raise SystemExit(main())
