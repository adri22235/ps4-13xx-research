#!/usr/bin/env python3
"""
PS4 WebKit ROP Gadget Finder — Firmware 14.00
==============================================
For use with libSceNKWebKit.sprx.decrypted from FW 14.00
Searches for ROP gadgets using byte patterns (same methodology as 13.04/13.50)

Usage:
    python3 find_webkit_gadgets_1400.py <path_to_webkit_binary>
    python3 find_webkit_gadgets_1400.py libSceNKWebKit.sprx.decrypted

Output:
    webkit_gadgets_1400.js  (ready to use in exploit chain)

Author: adri22235 + H4SS9M
Date: October 2026
Target: PS4 FW 14.00 (released September 16, 2026)
"""

import sys
import struct
import os
from datetime import datetime

# =============================================================================
# x86_64 ROP Gadget Byte Patterns
# =============================================================================
# These are the exact byte sequences for each instruction combination.
# Some gadgets are "clean" (just pop + ret), others are compound.

GADGETS = {
    # Basic control flow
    "wk_RET":         {"pattern": b"\xc3",             "desc": "ret"},
    "wk_LEAVE_RET":   {"pattern": b"\xc9\xc3",         "desc": "leave; ret"},

    # Standard register pops (single reg + ret)
    "wk_POP_RAX_RET": {"pattern": b"\x58\xc3",         "desc": "pop rax; ret"},
    "wk_POP_RBX_RET": {"pattern": b"\x5b\xc3",         "desc": "pop rbx; ret"},
    "wk_POP_RCX_RET": {"pattern": b"\x59\xc3",         "desc": "pop rcx; ret"},
    "wk_POP_RDX_RET": {"pattern": b"\x5a\xc3",         "desc": "pop rdx; ret"},
    "wk_POP_RSI_RET": {"pattern": b"\x5e\xc3",         "desc": "pop rsi; ret"},
    "wk_POP_RDI_RET": {"pattern": b"\x5f\xc3",         "desc": "pop rdi; ret"},
    "wk_POP_RBP_RET": {"pattern": b"\x5d\xc3",         "desc": "pop rbp; ret"},
    "wk_POP_RSP_RET": {"pattern": b"\x5c\xc3",         "desc": "pop rsp; ret"},

    # Extended register pops (REX prefix 0x41 + reg + ret)
    "wk_POP_R8_RET":  {"pattern": b"\x41\x58\xc3",     "desc": "pop r8; ret"},
    "wk_POP_R9_RET":  {"pattern": b"\x41\x59\xc3",     "desc": "pop r9; ret"},
    "wk_POP_R10_RET": {"pattern": b"\x41\x5a\xc3",     "desc": "pop r10; ret"},
    "wk_POP_R11_RET": {"pattern": b"\x41\x5b\xc3",     "desc": "pop r11; ret"},
    "wk_POP_R12_RET": {"pattern": b"\x41\x5c\xc3",     "desc": "pop r12; ret"},
    "wk_POP_R13_RET": {"pattern": b"\x41\x5d\xc3",     "desc": "pop r13; ret"},
    "wk_POP_R14_RET": {"pattern": b"\x41\x5e\xc3",     "desc": "pop r14; ret"},
    "wk_POP_R15_RET": {"pattern": b"\x41\x5f\xc3",     "desc": "pop r15; ret"},

    # Useful compound gadgets for stack pivoting and function calls
    "wk_MOV_RAX_RDI_RET":    {"pattern": b"\x48\x89\xf8\xc3",     "desc": "mov rax, rdi; ret"},
    "wk_MOV_RDI_RAX_RET":    {"pattern": b"\x48\x89\xc7\xc3",     "desc": "mov rdi, rax; ret"},
    "wk_MOV_RSI_RAX_RET":    {"pattern": b"\x48\x89\xc6\xc3",     "desc": "mov rsi, rax; ret"},
    "wk_MOV_RDX_RAX_RET":    {"pattern": b"\x48\x89\xc2\xc3",     "desc": "mov rdx, rax; ret"},
    "wk_XCHG_RAX_RSP_RET":   {"pattern": b"\x48\x94\xc3",         "desc": "xchg rax, rsp; ret (stack pivot!)"},

    # Memory access gadgets
    "wk_MOV_QWORD_RDI_RAX_RET":  {"pattern": b"\x48\x89\x07\xc3", "desc": "mov [rdi], rax; ret (write primitive)"},
    "wk_MOV_RAX_QWORD_RAX_RET":  {"pattern": b"\x48\x8b\x00\xc3", "desc": "mov rax, [rax]; ret (read primitive)"},
    "wk_MOV_RAX_QWORD_RDI_RET":  {"pattern": b"\x48\x8b\x07\xc3", "desc": "mov rax, [rdi]; ret (read primitive)"},

    # Arithmetic
    "wk_ADD_RAX_RCX_RET":    {"pattern": b"\x48\x01\xc8\xc3",     "desc": "add rax, rcx; ret"},
    "wk_SUB_RAX_RCX_RET":    {"pattern": b"\x48\x29\xc8\xc3",     "desc": "sub rax, rcx; ret"},
    "wk_XOR_RAX_RAX_RET":    {"pattern": b"\x48\x31\xc0\xc3",     "desc": "xor rax, rax; ret (zero rax)"},
    "wk_INC_RAX_RET":        {"pattern": b"\x48\xff\xc0\xc3",     "desc": "inc rax; ret"},

    # Syscall related
    "wk_SYSCALL_RET":        {"pattern": b"\x0f\x05\xc3",         "desc": "syscall; ret"},

    # JOP gadgets (jump-oriented)
    "wk_JMP_RAX":            {"pattern": b"\xff\xe0",              "desc": "jmp rax"},
    "wk_CALL_RAX":           {"pattern": b"\xff\xd0",              "desc": "call rax"},
    "wk_JMP_RCX":            {"pattern": b"\xff\xe1",              "desc": "jmp rcx"},
}

# Compound/chained gadgets to search with relaxed patterns
COMPOUND_GADGETS = {
    "wk_POP_RDI_POP_RSI_RET": {
        "pattern": b"\x5f\x5e\xc3",
        "desc": "pop rdi; pop rsi; ret (2 args setup)"
    },
    "wk_POP_RDI_POP_RSI_POP_RDX_RET": {
        "pattern": b"\x5f\x5e\x5a\xc3",
        "desc": "pop rdi; pop rsi; pop rdx; ret (3 args setup)"
    },
    "wk_POP_R13_POP_R14_POP_R15_RET": {
        "pattern": b"\x41\x5d\x41\x5e\x41\x5f\xc3",
        "desc": "pop r13; pop r14; pop r15; ret"
    },
    "wk_POP_RBX_POP_RBP_RET": {
        "pattern": b"\x5b\x5d\xc3",
        "desc": "pop rbx; pop rbp; ret"
    },
}


def find_all_occurrences(data: bytes, pattern: bytes) -> list:
    """Find all occurrences of a byte pattern in binary data."""
    results = []
    start = 0
    while True:
        idx = data.find(pattern, start)
        if idx == -1:
            break
        results.append(idx)
        start = idx + 1
    return results


def find_gadgets(binary_path: str) -> dict:
    """
    Search for all ROP gadgets in the WebKit binary.
    Returns dict of gadget_name -> (best_offset, all_offsets)
    """
    print(f"\n[*] Loading binary: {binary_path}")
    with open(binary_path, "rb") as f:
        data = f.read()

    file_size = len(data)
    print(f"[*] Binary size: {file_size:,} bytes ({file_size / (1024*1024):.1f} MB)")
    print(f"[*] Searching for {len(GADGETS) + len(COMPOUND_GADGETS)} gadget patterns...\n")

    results = {}

    # Search standard gadgets
    for name, info in GADGETS.items():
        occurrences = find_all_occurrences(data, info["pattern"])
        if occurrences:
            # Prefer lower addresses (more likely to be in .text section)
            best = occurrences[0]
            results[name] = {
                "offset": best,
                "count": len(occurrences),
                "all": occurrences[:5],  # Keep first 5 for reference
                "desc": info["desc"],
                "pattern": info["pattern"].hex(),
            }
            status = "OK" if len(occurrences) > 0 else "!!"
            print(f"  [{status}] {name:30s} @ 0x{best:08x}  ({len(occurrences):4d} found)  // {info['desc']}")
        else:
            results[name] = None
            print(f"  [!!] {name:30s} NOT FOUND                     // {info['desc']}")

    print(f"\n[*] Searching compound gadgets...\n")

    # Search compound gadgets
    for name, info in COMPOUND_GADGETS.items():
        occurrences = find_all_occurrences(data, info["pattern"])
        if occurrences:
            best = occurrences[0]
            results[name] = {
                "offset": best,
                "count": len(occurrences),
                "all": occurrences[:5],
                "desc": info["desc"],
                "pattern": info["pattern"].hex(),
            }
            print(f"  [OK] {name:40s} @ 0x{best:08x}  ({len(occurrences):4d} found)  // {info['desc']}")
        else:
            results[name] = None
            print(f"  [!!] {name:40s} NOT FOUND                     // {info['desc']}")

    return results


def generate_js(results: dict, binary_path: str) -> str:
    """Generate webkit_gadgets_1400.js from found gadgets."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    file_size = os.path.getsize(binary_path)

    js = f"""// WebKit ROP Gadgets — PS4 Firmware 14.00
// Source: {os.path.basename(binary_path)} ({file_size / (1024*1024):.0f} MB)
// Generated: {timestamp} by find_webkit_gadgets_1400.py
// Method: Byte pattern search (same methodology as 13.04/13.50)
// Author: adri22235 + H4SS9M
//
// FW 14.00 released: September 16, 2026
// Kernel offsets: see 1400_offsets.txt / 1400.c

const webkit_gadgets_1400 = {{
"""

    # Standard gadgets
    for name, info in results.items():
        if name.startswith("wk_") and info is not None and not name.startswith("wk_POP_RDI_POP") and not name.startswith("wk_POP_R13_POP") and not name.startswith("wk_POP_RBX_POP") and not name.startswith("wk_POP_RDI_POP_RSI_POP"):
            js += f"  {name:30s}: 0x{info['offset']:x},    // {info['desc']} ({info['count']} found, pattern: {info['pattern']})\n"

    js += "\n  // Compound gadgets (multi-pop chains)\n"
    for name in COMPOUND_GADGETS:
        if name in results and results[name] is not None:
            info = results[name]
            js += f"  {name:30s}: 0x{info['offset']:x},    // {info['desc']}\n"

    js += """};\n
// Kernel offsets for 14.00 (from 1400_offsets.txt):
// PRISON0    = 0x0111FA18  (unchanged from 13.04)
// ROOTVNODE  = 0x02136E90  (unchanged from 13.04)
// ALLPROC    = 0x01B28538
// SYSENT     = 0x01102B70

// Usage with CSSFontFace exploit:
//   1. Load this file in your exploit HTML page
//   2. Use gadgets to build ROP chain after WebKit UAF trigger
//   3. Pivot stack with wk_XCHG_RAX_RSP_RET
//   4. Chain: set up args -> call kernel function -> profit
//
// Comparison methodology:
//   - BinDiff webkit_gadgets_1350.js addresses against these
//   - Delta analysis shows offset shifts between FW versions
//   - If a gadget moved, check alternative occurrences in .all array

module.exports = { webkit_gadgets_1400 };
"""
    return js


def generate_delta_report(results: dict) -> str:
    """Compare found gadgets against known 13.50 offsets."""
    known_1350 = {
        "wk_RET":          0x3cbc51b,
        "wk_LEAVE_RET":    0x182f7,
        "wk_POP_RAX_RET":  0x10504,
        "wk_POP_RBX_RET":  0x79e8,
        "wk_POP_RCX_RET":  0x1bade,
        "wk_POP_RDI_RET":  0x5c480,
        "wk_POP_RDX_RET":  0x12c5ba,
        "wk_POP_RSI_RET":  0x6e45e,
        "wk_POP_RBP_RET":  0x3ccc7a2,
        "wk_POP_RSP_RET":  0x3cbc51a,
        "wk_POP_R8_RET":   0x5c47f,
        "wk_POP_R9_RET":   0x9db883,
        "wk_POP_R12_RET":  0x2426b15,
    }

    report = "\n" + "=" * 70
    report += "\n  DELTA ANALYSIS: FW 13.50 → 14.00\n"
    report += "=" * 70 + "\n\n"
    report += f"  {'Gadget':30s} {'13.50':>12s} {'14.00':>12s} {'Delta':>12s}\n"
    report += "  " + "-" * 66 + "\n"

    for name, addr_1350 in known_1350.items():
        if name in results and results[name] is not None:
            addr_1400 = results[name]["offset"]
            delta = addr_1400 - addr_1350
            sign = "+" if delta >= 0 else ""
            report += f"  {name:30s} 0x{addr_1350:08x}   0x{addr_1400:08x}   {sign}{delta:#x}\n"
        else:
            report += f"  {name:30s} 0x{addr_1350:08x}   {'NOT FOUND':>12s}   {'N/A':>12s}\n"

    return report


def main():
    if len(sys.argv) < 2:
        print("""
╔══════════════════════════════════════════════════════════╗
║  PS4 WebKit ROP Gadget Finder — Firmware 14.00          ║
║  For security research on your own console              ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║  Usage:                                                  ║
║    python3 find_webkit_gadgets_1400.py <webkit_binary>   ║
║                                                          ║
║  Example:                                                ║
║    python3 find_webkit_gadgets_1400.py \\                 ║
║      libSceNKWebKit.sprx.decrypted                       ║
║                                                          ║
║  Output: webkit_gadgets_1400.js                          ║
║                                                          ║
║  Get the binary:                                         ║
║    1. Dump from PS4 on FW 14.00 via BD-JB userland       ║
║    2. Decrypt sprx: orbis-lib-tool --decrypt              ║
║    3. Run this script on the decrypted lib                ║
║                                                          ║
║  adri22235 + H4SS9M // October 2026                      ║
╚══════════════════════════════════════════════════════════╝
""")
        sys.exit(1)

    binary_path = sys.argv[1]

    if not os.path.isfile(binary_path):
        print(f"[!] Error: File not found: {binary_path}")
        sys.exit(1)

    # Find all gadgets
    results = find_gadgets(binary_path)

    # Count results
    found = sum(1 for v in results.values() if v is not None)
    total = len(results)
    print(f"\n[*] Found {found}/{total} gadgets")

    # Generate delta report (compare against 13.50)
    delta = generate_delta_report(results)
    print(delta)

    # Generate JS output
    js_content = generate_js(results, binary_path)
    output_path = "webkit_gadgets_1400.js"
    with open(output_path, "w") as f:
        f.write(js_content)
    print(f"\n[+] Saved: {output_path}")
    print(f"[+] Ready for CSSFontFace exploit chain on FW 14.00!")
    print(f"[+] Next: BinDiff against webkit_gadgets_1350.js for verification\n")


if __name__ == "__main__":
    main()
