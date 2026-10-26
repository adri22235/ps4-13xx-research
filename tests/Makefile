CC      := gcc
CFLAGS  := -Wall -Wextra -O2 -pthread -std=gnu11
TARGETS := test_sound_mmap_race test_semctl_kernel_rw test_execve_args_overflow \
           test_rop_dispatcher_1400 test_cred_root_patch

all: $(TARGETS)

test_sound_mmap_race: test_sound_mmap_race.c
	$(CC) $(CFLAGS) $< -o $@

test_semctl_kernel_rw: test_semctl_kernel_rw.c
	$(CC) $(CFLAGS) $< -o $@

test_execve_args_overflow: test_execve_args_overflow.c
	$(CC) $(CFLAGS) $< -o $@

test_rop_dispatcher_1400: test_rop_dispatcher_1400.c
	$(CC) $(CFLAGS) $< -o $@

test_cred_root_patch: test_cred_root_patch.c
	$(CC) $(CFLAGS) $< -o $@

run-all: all
	@echo "================================================================="
	@echo "  RUNNING FULL MEMORY SAFETY & KERNEL VERIFICATION TEST SUITE"
	@echo "  Target: PS4 / PS5 FreeBSD Kernel (Orbis & Prospero OS)"
	@echo "  Standards: ISO/IEC 29147 CVD / García Casado Security Research"
	@echo "================================================================="
	@echo ""
	@echo "--- [1/5] Testing CVE-2026-101308: sound(4) mmap UAF Race ---"
	@./test_sound_mmap_race
	@echo ""
	@echo "--- [2/5] Testing CVE-2026-58087: semctl 15-bit wrap-around ---"
	@./test_semctl_kernel_rw
	@echo ""
	@echo "--- [3/5] Testing CVE-2026-7270: execve slab overflow ---"
	@./test_execve_args_overflow
	@echo ""
	@echo "--- [4/5] Testing ROP Dispatcher & ABI Stack Alignment ---"
	@./test_rop_dispatcher_1400
	@echo ""
	@echo "--- [5/5] Testing Credential Root Elevation & Jailbreak ---"
	@./test_cred_root_patch
	@echo ""
	@echo "================================================================="
	@echo "  [✓] ALL 5 HARNESSES COMPILED & EXECUTED WITH ZERO ERRORS"
	@echo "================================================================="

clean:
	rm -f $(TARGETS)

.PHONY: all clean run-all
