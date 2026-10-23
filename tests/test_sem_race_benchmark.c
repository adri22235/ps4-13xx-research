#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#define TARGET_CYCLES 32768 /* 0x8000 15-bit wrap limit */

static double get_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

int main(void) {
    key_t key = (key_t)(0x13370000 | (getpid() & 0xFFFF));
    printf("[*] Starting SysV Semaphore Recycle Benchmark\n");
    printf("[*] Target cycles: %d (0x%X - FreeBSD 15-bit sequence wrap)\n", TARGET_CYCLES, TARGET_CYCLES);

    double t_start = get_time_sec();
    int successful_cycles = 0;

    for (int i = 0; i < TARGET_CYCLES; i++) {
        int semid = semget(key, 1, IPC_CREAT | IPC_EXCL | 0600);
        if (semid != -1) {
            if (semctl(semid, 0, IPC_RMID) == 0) {
                successful_cycles++;
            }
        } else {
            /* Try to clean up and recreate */
            semid = semget(key, 1, 0600);
            if (semid != -1) semctl(semid, 0, IPC_RMID);
        }
    }

    double t_end = get_time_sec();
    double elapsed = t_end - t_start;
    double rate = successful_cycles / elapsed;

    printf("[+] Completed %d / %d cycles\n", successful_cycles, TARGET_CYCLES);
    printf("[+] Elapsed time: %.4f seconds\n", elapsed);
    printf("[+] Throughput: %.2f cycles/second\n", rate);
    printf("[+] Time required to achieve 0x8000 wrap: ~%.2f ms\n", (TARGET_CYCLES / rate) * 1000.0);

    return 0;
}
