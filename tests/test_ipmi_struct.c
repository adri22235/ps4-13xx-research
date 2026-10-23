#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define SYS_IPMIMGR_CALL 622

/* IPMI Manager descriptor layout for Orbis OS (FreeBSD 9 ABI) */
struct ipmi_cmd_desc {
    uint32_t cmd_id;       /* Offset 0x00 */
    uint32_t flags;        /* Offset 0x04 */
    uint64_t user_buf;     /* Offset 0x08 */
    uint32_t buf_len;      /* Offset 0x10 */
    uint32_t reserved;     /* Offset 0x14 */
    uint64_t callback_ctx; /* Offset 0x18 */
};

int main(void) {
    printf("[*] Testing IPMI Descriptor Struct Alignment (Syscall 622 ABI)\n");
    printf("    sizeof(struct ipmi_cmd_desc) = %zu bytes (expected 0x20 / 32)\n", sizeof(struct ipmi_cmd_desc));
    printf("    offsetof(cmd_id)       = 0x%02zx\n", offsetof(struct ipmi_cmd_desc, cmd_id));
    printf("    offsetof(flags)        = 0x%02zx\n", offsetof(struct ipmi_cmd_desc, flags));
    printf("    offsetof(user_buf)     = 0x%02zx\n", offsetof(struct ipmi_cmd_desc, user_buf));
    printf("    offsetof(buf_len)      = 0x%02zx\n", offsetof(struct ipmi_cmd_desc, buf_len));
    printf("    offsetof(callback_ctx) = 0x%02zx\n", offsetof(struct ipmi_cmd_desc, callback_ctx));

    if (sizeof(struct ipmi_cmd_desc) == 32 &&
        offsetof(struct ipmi_cmd_desc, user_buf) == 8 &&
        offsetof(struct ipmi_cmd_desc, callback_ctx) == 24) {
        printf("[+] ABI Structure packing matches Orbis OS sub_EF1E70 specification perfectly!\n");
        return 0;
    } else {
        printf("[-] Warning: Struct alignment mismatch!\n");
        return 1;
    }
}
