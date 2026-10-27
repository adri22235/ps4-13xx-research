#!/usr/bin/env python3
"""
PS4 FW 14.00 Kernel Analyzer
Extrae funciones, offsets y estructura del kernel dump.
Para usar con Ghidra headless o standalone con capstone/lief.

Uso:
  python3 ps4_kernel_analyzer.py <kernel.elf> [--output offsets.txt]

Para Ghidra headless:
  analyzeHeadless /tmp/ghidra_project ps4_1400 \
    -import 1400_ps4k.elf \
    -processor x86:LE:64:default \
    -postScript ps4_ghidra_export.py
"""

import sys
import struct
import re
from pathlib import Path

try:
    import lief
    HAS_LIEF = True
except ImportError:
    HAS_LIEF = False

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False


KERNEL_BASE = 0xFFFFFFFF82200000

# Funciones clave para investigación de seguridad PS4
# Estas son las que la scene necesita para kernel exploits
KEY_FUNCTIONS = [
    # Seguridad / Auth
    b"sceSblAuthMgrIsLoadable",
    b"sceSblAuthMgrVerifyHeader",
    b"sceSblAuthMgrSmIsLoadable2",
    b"sceSblAuthMgrLoadSelfBlock",
    b"sceSblAuthMgrSmLoadSelfBlock",
    # Keymgr
    b"sceSblKeymgrSmCallfuncWithID",
    # Servicios SBL
    b"sceSblServiceMailbox",
    b"sceSblServiceRequest",
    # PFS
    b"sceSblPfsSaveDataUpdateAuthCode",
    # Kernel
    b"copyin",
    b"copyout",
    b"copyinstr",
    # Memory
    b"sceKernelReleaseDirectMemory",
    # Dynlib
    b"kern_dynlib",
]

# Patrones de bytes conocidos en kernels FreeBSD/PS4
# para localizar funciones sin símbolos
PATTERNS = {
    "syscall_handler_prologue": bytes([
        0x55,                   # push rbp
        0x48, 0x89, 0xE5,      # mov rbp, rsp
        0x41, 0x57,             # push r15
        0x41, 0x56,             # push r14
        0x41, 0x55,             # push r13
        0x41, 0x54,             # push r12
        0x53,                   # push rbx
    ]),
    "ret_instruction": bytes([0xC3]),
    "xor_rax_rax_ret": bytes([0x48, 0x31, 0xC0, 0xC3]),  # xor rax,rax; ret
    "mov_rax_0_ret": bytes([0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, 0xC3]),
}


def read_elf_basic(filepath):
    """Lee el ELF sin dependencias externas."""
    with open(filepath, "rb") as f:
        data = f.read()

    # ELF header
    magic = data[:4]
    if magic != b"\x7fELF":
        print("ERROR: No es un archivo ELF válido")
        sys.exit(1)

    ei_class = data[4]  # 2 = 64-bit
    ei_osabi = data[7]  # 9 = FreeBSD

    entry = struct.unpack_from("<Q", data, 24)[0]
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize = struct.unpack_from("<H", data, 54)[0]
    phnum = struct.unpack_from("<H", data, 56)[0]

    segments = []
    for i in range(phnum):
        off = phoff + i * phentsize
        ptype = struct.unpack_from("<I", data, off)[0]
        pflags = struct.unpack_from("<I", data, off + 4)[0]
        p_offset = struct.unpack_from("<Q", data, off + 8)[0]
        p_vaddr = struct.unpack_from("<Q", data, off + 16)[0]
        p_filesz = struct.unpack_from("<Q", data, off + 32)[0]
        p_memsz = struct.unpack_from("<Q", data, off + 40)[0]
        segments.append({
            "type": ptype,
            "flags": pflags,
            "offset": p_offset,
            "vaddr": p_vaddr,
            "filesz": p_filesz,
            "memsz": p_memsz,
        })

    return {
        "class": ei_class,
        "osabi": ei_osabi,
        "entry": entry,
        "segments": segments,
        "data": data,
    }


def find_string_refs(data, target_string):
    """Encuentra todas las ocurrencias de un string en el binario."""
    results = []
    search = target_string if isinstance(target_string, bytes) else target_string.encode()
    start = 0
    while True:
        pos = data.find(search, start)
        if pos == -1:
            break
        vaddr = KERNEL_BASE + pos
        results.append({"file_offset": pos, "vaddr": vaddr})
        start = pos + 1
    return results


def find_pattern(data, pattern, max_results=100):
    """Encuentra un patrón de bytes en el binario."""
    results = []
    start = 0
    while len(results) < max_results:
        pos = data.find(pattern, start)
        if pos == -1:
            break
        vaddr = KERNEL_BASE + pos
        results.append({"file_offset": pos, "vaddr": vaddr})
        start = pos + 1
    return results


def extract_strings_with_offsets(data, min_length=8):
    """Extrae strings con sus offsets virtuales."""
    results = []
    current = b""
    start_pos = 0

    for i, byte in enumerate(data):
        if 0x20 <= byte < 0x7F:
            if not current:
                start_pos = i
            current += bytes([byte])
        else:
            if len(current) >= min_length:
                vaddr = KERNEL_BASE + start_pos
                results.append({
                    "string": current.decode("ascii", errors="replace"),
                    "file_offset": start_pos,
                    "vaddr": vaddr,
                })
            current = b""

    return results


def find_function_by_string_xref(data, func_name_bytes, text_end_offset):
    """
    Busca un string en el binario y luego busca referencias (LEA) a esa dirección
    en el segmento de texto para localizar la función que lo usa.
    """
    # Encontrar el string
    str_refs = find_string_refs(data, func_name_bytes)
    if not str_refs:
        return None

    str_vaddr = str_refs[0]["vaddr"]

    # Buscar LEA rdi, [rip + offset] que apunte a este string
    # En x86-64, LEA usa direccionamiento RIP-relative
    candidates = []

    for i in range(0, min(text_end_offset, len(data)) - 7):
        # LEA reg, [rip+disp32]: 48 8D 3D xx xx xx xx (LEA rdi)
        #                        48 8D 35 xx xx xx xx (LEA rsi)
        #                        48 8D 0D xx xx xx xx (LEA rcx)
        if data[i] == 0x48 and data[i+1] == 0x8D and data[i+2] in (0x3D, 0x35, 0x0D, 0x05, 0x15, 0x1D, 0x25, 0x2D):
            disp = struct.unpack_from("<i", data, i + 3)[0]
            target = KERNEL_BASE + i + 7 + disp  # RIP + 7 (instrucción) + displacement
            if target == str_vaddr:
                # Buscar el inicio de función (retroceder hasta encontrar el prólogo)
                func_start = i
                for j in range(i, max(i - 256, 0), -1):
                    # push rbp; mov rbp, rsp
                    if data[j] == 0x55 and j + 3 < len(data) and data[j+1:j+4] == b"\x48\x89\xe5":
                        func_start = j
                        break
                    # O un ret/int3 anterior (fin de función previa)
                    if data[j] == 0xC3 or data[j] == 0xCC:
                        func_start = j + 1
                        # Alinear a 16 bytes (común en compiladores)
                        while func_start % 16 != 0 and func_start < i:
                            if data[func_start] == 0xCC or data[func_start] == 0x90:
                                func_start += 1
                            else:
                                break
                        break

                candidates.append({
                    "xref_offset": i,
                    "xref_vaddr": KERNEL_BASE + i,
                    "func_start_offset": func_start,
                    "func_start_vaddr": KERNEL_BASE + func_start,
                })

    return candidates if candidates else None


def analyze_kernel(filepath, output_path=None):
    """Análisis principal del kernel."""
    print(f"=== PS4 FW 14.00 KERNEL ANALYZER ===")
    print(f"Archivo: {filepath}")
    print()

    elf = read_elf_basic(filepath)
    data = elf["data"]

    print(f"Kernel base:  {KERNEL_BASE:#018x}")
    print(f"Entry point:  {elf['entry']:#018x}")
    print(f"Tamaño:       {len(data)} bytes ({len(data)/1024/1024:.2f} MB)")
    print(f"OS/ABI:       FreeBSD ({elf['osabi']:#x})")
    print()

    # Segmento de texto (código ejecutable)
    text_seg = None
    for seg in elf["segments"]:
        if seg["type"] == 1 and seg["flags"] & 1:  # LOAD + EXEC
            text_seg = seg
            break

    if text_seg:
        text_end = text_seg["filesz"]
        print(f"Segmento TEXT: {text_seg['vaddr']:#018x} - {text_seg['vaddr'] + text_seg['filesz']:#018x}")
        print(f"  Tamaño: {text_seg['filesz']} bytes ({text_seg['filesz']/1024/1024:.2f} MB)")
    else:
        text_end = len(data)
        print("AVISO: No se encontró segmento TEXT explícito")
    print()

    # Buscar strings de funciones clave y sus xrefs
    print("=== BUSCANDO FUNCIONES CLAVE POR STRING XREF ===")
    print()

    results = {}

    for func_name in KEY_FUNCTIONS:
        name = func_name.decode()
        refs = find_string_refs(data, func_name)
        if refs:
            print(f"  {name}:")
            print(f"    String en: {refs[0]['vaddr']:#018x} (offset {refs[0]['file_offset']:#x})")

            # Buscar xrefs al string
            xrefs = find_function_by_string_xref(data, func_name, text_end)
            if xrefs:
                for xr in xrefs[:3]:  # Max 3 xrefs
                    print(f"    XREF en:  {xr['xref_vaddr']:#018x}")
                    print(f"    Func ~:   {xr['func_start_vaddr']:#018x} (offset {xr['func_start_offset']:#x})")
                results[name] = {
                    "string_vaddr": refs[0]["vaddr"],
                    "xrefs": xrefs,
                }
            else:
                print(f"    (sin xrefs en texto)")
                results[name] = {"string_vaddr": refs[0]["vaddr"], "xrefs": None}
        else:
            print(f"  {name}: NO ENCONTRADO")
        print()

    # Buscar patrones conocidos
    print("=== PATRONES DE BYTES ===")
    print()

    for pat_name, pattern in PATTERNS.items():
        hits = find_pattern(data, pattern, max_results=10)
        print(f"  {pat_name}: {len(hits)} ocurrencias")
        if hits and pat_name != "ret_instruction":
            for h in hits[:5]:
                print(f"    {h['vaddr']:#018x} (offset {h['file_offset']:#x})")
    print()

    # Guardar resultados
    if output_path:
        with open(output_path, "w") as f:
            f.write("# PS4 FW 14.00 - KERNEL OFFSETS\n")
            f.write(f"# Build: J02699045\n")
            f.write(f"# Kernel base: {KERNEL_BASE:#018x}\n")
            f.write(f"# Entry point: {elf['entry']:#018x}\n")
            f.write(f"# Generado: análisis de 1400_ps4k.elf\n")
            f.write(f"# TODOS LOS OFFSETS SON RELATIVOS A KERNEL BASE\n")
            f.write(f"\n")

            for name, info in sorted(results.items()):
                f.write(f"\n## {name}\n")
                f.write(f"string_addr = {info['string_vaddr']:#018x}\n")
                if info.get("xrefs"):
                    for i, xr in enumerate(info["xrefs"][:3]):
                        offset_from_base = xr["func_start_vaddr"] - KERNEL_BASE
                        f.write(f"func_approx_{i} = {xr['func_start_vaddr']:#018x}  # offset: {offset_from_base:#x}\n")

            f.write(f"\n\n# NOTA: Estas direcciones son APROXIMADAS.\n")
            f.write(f"# Para offsets exactos, cargar en Ghidra con base {KERNEL_BASE:#x}\n")
            f.write(f"# y verificar cada función con el auto-análisis.\n")

        print(f"Resultados guardados en: {output_path}")

    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Uso: {sys.argv[0]} <kernel.elf> [--output offsets.txt]")
        sys.exit(1)

    kernel_path = sys.argv[1]
    output = None
    if "--output" in sys.argv:
        idx = sys.argv.index("--output")
        if idx + 1 < len(sys.argv):
            output = sys.argv[idx + 1]

    analyze_kernel(kernel_path, output)
