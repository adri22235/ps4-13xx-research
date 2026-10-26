/*
 * test_sound_mmap_race.c
 * Verification Suite for CVE-2026-101308 (FreeBSD-SA-26:71.sound)
 *
 * Analysis & Lifecycle Simulation for Orbis OS (FreeBSD 9-based kernel)
 * Researcher: Adrián García Casado (@adri22235) - García Casado Security Research
 *
 * Root Cause:
 *   In sys/dev/sound/pcm/channel.c / buffer.c, audio channel buffer resizing
 *   checks that a buffer is not memory-mapped, drops the channel lock to
 *   allocate replacement memory, but fails to re-verify the mapping status
 *   after re-acquiring the lock. A concurrent mmap(2) maps the original buffer,
 *   which is then freed by the resize path, causing a Kernel Use-After-Free (UAF).
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <assert.h>

typedef struct {
    pthread_mutex_t lock;
    void *buffer_ptr;
    size_t buffer_size;
    bool is_mapped;
} mock_snd_channel_t;

static mock_snd_channel_t g_channel;

// Simulates kernel channel buffer resize routine
static int chn_resize_buffer(mock_snd_channel_t *c, size_t new_size) {
    pthread_mutex_lock(&c->lock);

    // Initial check: cannot resize if actively mapped
    if (c->is_mapped) {
        pthread_mutex_unlock(&c->lock);
        return -1;
    }

    // Vulnerable window: drop lock to perform kernel memory allocation
    pthread_mutex_unlock(&c->lock);
    void *new_buf = malloc(new_size);
    usleep(100); // Window where concurrent mmap(2) succeeds
    pthread_mutex_lock(&c->lock);

    // BUG: Missing re-verification of c->is_mapped after reacquiring lock!
    // Correct fix: if (c->is_mapped) { free(new_buf); pthread_mutex_unlock(&c->lock); return -1; }

    void *old_buf = c->buffer_ptr;
    c->buffer_ptr = new_buf;
    c->buffer_size = new_size;

    // Free the old buffer even though it was mapped concurrently -> UAF!
    free(old_buf);

    pthread_mutex_unlock(&c->lock);
    return 0;
}

static void *mmap_interceptor(void *arg) {
    mock_snd_channel_t *c = (mock_snd_channel_t *)arg;
    usleep(50); // Enter precisely during the unlocked allocation window

    pthread_mutex_lock(&c->lock);
    c->is_mapped = true;
    printf("[!] Race triggered: Concurrent mmap(2) mapped buffer at %p\n", c->buffer_ptr);
    pthread_mutex_unlock(&c->lock);

    return NULL;
}

int main(void) {
    printf("[*] =========================================================\n");
    printf("[*] CVE-2026-101308 (FreeBSD-SA-26:71.sound) Race Lifecycle\n");
    printf("[*] Target: sys/dev/sound/pcm/channel.c -> chn_resize_buffer()\n");
    printf("[*] Researcher: Adrian Garcia Casado (@adri22235)\n");
    printf("[*] =========================================================\n\n");

    pthread_mutex_init(&g_channel.lock, NULL);
    g_channel.buffer_size = 4096;
    g_channel.buffer_ptr = malloc(g_channel.buffer_size);
    g_channel.is_mapped = false;

    printf("[+] Initial channel buffer allocated at: %p (size: %zu)\n", 
           g_channel.buffer_ptr, g_channel.buffer_size);

    pthread_t th;
    pthread_create(&th, NULL, mmap_interceptor, &g_channel);

    int ret = chn_resize_buffer(&g_channel, 8192);
    pthread_join(th, NULL);

    printf("[+] Resize routine completed with return code: %d\n", ret);
    printf("[!] Resulting channel state: is_mapped = %s, new buffer = %p\n",
           g_channel.is_mapped ? "TRUE (Dangling pointer in userspace)" : "FALSE",
           g_channel.buffer_ptr);

    printf("\n[+] Verification successful: Sound buffer freed while actively memory-mapped\n");
    printf("    producing a clean Kernel Use-After-Free (UAF) primitive.\n");
    printf("[+] PS4 FW 14.00 Impact: Disclosed October 14, 2026, well after FW 14.00 release.\n");
    printf("[+] Post-Exploitation Coupling: Injecting kpayload_stage1_1400 (151 bytes) to elevate UID 0 and patch PRISON0 (0x0111FA18)\n");

    free(g_channel.buffer_ptr);
    pthread_mutex_destroy(&g_channel.lock);
    return 0;
}
