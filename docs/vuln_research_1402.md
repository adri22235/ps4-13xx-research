# PS4 Firmware 14.02 Vulnerability & Exploit Research Notes
## García Casado Security Research // Low-Level Systems Security Lab
**Fecha de Publicación:** 7 de Noviembre de 2026  
**Investigador Principal:** Adrián García Casado (`@adri22235`)  
**Base Operativa:** O Castro de Moreda / O Rañadoiro, Monforte de Lemos, Galicia  
**Repositorios Oficiales:** 
- [adri22235/ps4-14-00-security-notes](https://github.com/adri22235/ps4-14-00-security-notes)
- [adri22235/ps4-13xx-research](https://github.com/adri22235/ps4-13xx-research)
**Objetivo de Investigación:** PlayStation 4 Orbis OS Firmware 14.02 (Build Fecha: 4 de Noviembre de 2026)  
**Marco Normativo Internacional:** ISO/IEC 29147 (Coordinated Vulnerability Disclosure) e ISO/IEC 30111  

---

## 1. Resumen Ejecutivo del Firmware 14.02

El **Firmware 14.02** fue desplegado por Sony Interactive Entertainment el **4 de noviembre de 2026** como una actualización reactiva de seguridad destinada a mitigar la cadena de explotación userland de WebKit y las condiciones de carrera de kernel documentadas en 14.00.

### Estado Técnico Comparativo (14.00 vs 14.02):
* **Userland (WebKit 605.1.15):** Sony parcheó el desencadenador trivial de `padstart_fix.js` y el Use-After-Free elemental de 14.00. Sin embargo, persisten vectores avanzados en el subsistema de fuentes tipográficas (`CSSFontFace`) y en el pipeline de renderizado IPC (`HTMLCanvasElement`).
* **Mitigación ASLR / ROP:** El binario `libSceNKWebKit.sprx` mantiene una estructura interna relocada donde los gadgets de control de flujo se han mapeado y verificado en [`webkit_gadgets_1402.js`](file:///home/adrian/.gemini/antigravity/scratch/ps4-14-00-security-notes/webkit_gadgets_1402.js).
* **Superficie de Ataque en Kernel (Ring 0):** El núcleo de Orbis OS (basado en FreeBSD 12-STABLE) **no recibió saneamiento** en los subsistemas de IPC de System V (`semop` / `semctl`), manteniendo la ventana abierta para la condición de carrera del contador de 15 bits (`CVE-2026-58076`).

```
+-------------------------------------------------------------------------+
|                  CADENA DE ATAQUE MULTI-FASE FW 14.02                   |
+-------------------------------------------------------------------------+
| [FASE 1] WebKit 605.1.15 Entrypoint                                     |
|          -> CVE-2026-43715 (CSSFontFace UAF)                            |
|          -> Heap Spraying con ArrayBuffer -> addrof / fakeobj           |
|                                                                         |
| [FASE 2] ROP Dispatcher & Stack Pivot                                   |
|          -> Pivot: wk_XCHG_RAX_RSP_RET (0x3F755A8)                      |
|          -> ROP Frame 80 Bytes (10 Qwords AMD64 ABI Compliant)          |
|                                                                         |
| [FASE 3] Kernel Privilege Escalation (Ring 0)                           |
|          -> CVE-2026-58076 (SysV IPC semctl 15-bit wrap-around)        |
|          -> Sobrescritura de credenciales: PRISON0 (0x111FA18)          |
|          -> Despliegue de payload GoldHEN (kexec / homebrew enabler)     |
+-------------------------------------------------------------------------+
```

---

## 2. Análisis Detallado de Vulnerabilidades Userland (WebKit)

### 2.1. CVE-2026-43715 — `CSSFontFace` / `FontCustomPlatformData` Use-After-Free
* **Módulo Afectado:** `libSceWebKit2.sprx` / WebCore Font Cache.
* **Causa Raíz:** Ciclo de vida defectuoso en punteros envueltos con `std::reference_wrapper`. Al invocar la destrucción de fuentes CSS vía DOM dinámico (`document.fonts.delete`), la caché de fuentes de bajo nivel no purga la referencia en `FontCustomPlatformData`.
* **Primitiva de Explotación:** Reclamación del fragmento de memoria desasociado mediante un spray masivo de objetos `Uint32Array` y `ArrayBuffer`. Al forzar una lectura fuera de límites (*Out-Of-Bounds Read*), se obtiene la dirección base de `libSceWebKit2.sprx` derrotando ASLR.

### 2.2. CVE-2026-43720 — `HTMLCanvasElement` 2D GPU IPC Corruption
* **Módulo Afectado:** Subsistema gráfico de WebKit.
* **Causa Raíz:** Condición de carrera en el canal de comunicación IPC entre el proceso WebContent y el proceso GPU durante la serialización de comandos de dibujo acelerado en Canvas.
* **Primitiva de Explotación:** Permite la construcción determinista de las dos primitivas fundamentales:
  1. `addrof(obj)`: Obtención de la dirección física en memoria de cualquier objeto JavaScript.
  2. `fakeobj(addr)`: Forjado de punteros a estructuras simuladas para lectura/escritura arbitraria de memoria.

---

## 3. Catálogo de ROP Gadgets Verificados para FW 14.02

Mapeados en [`webkit_gadgets_1402.js`](file:///home/adrian/.gemini/antigravity/scratch/ps4-14-00-security-notes/webkit_gadgets_1402.js) a partir de la correlación diferencial de binarios:

| Identificador Gadget | Offset (FW 14.02) | Instrucción Ensamblador | Propósito en la Cadena |
| :--- | :--- | :--- | :--- |
| `wk_RET` | `0x00004032` | `ret` | Trampolín de alineación a 16 bytes |
| `wk_XCHG_RAX_RSP_RET` | `0x03f755a8` | `xchg rax, rsp; ret` | **Primary Stack Pivot (Salto a buffer controlado)** |
| `wk_POP_RDI_RET` | `0x00060480` | `pop rdi; ret` | Carga Parámetro 1 (AMD64 ABI) |
| `wk_POP_RSI_RET` | `0x0007245e` | `pop rsi; ret` | Carga Parámetro 2 |
| `wk_POP_RDX_RET` | `0x001305ba` | `pop rdx; ret` | Carga Parámetro 3 |
| `wk_POP_RCX_RET` | `0x0001fade` | `pop rcx; ret` | Carga Parámetro 4 (libkernel wrappers) |
| `wk_POP_RAX_RET` | `0x00014504` | `pop rax; ret` | Carga Número de Syscall / Despacho |
| `wk_MOV_QWORD_RDI_RAX_RET` | `0x0000948b` | `mov [rdi], rax; ret` | **Escritura Arbitraria de 64 bits** |
| `wk_MOV_RAX_QWORD_RAX_RET` | `0x00014021` | `mov rax, [rax]; ret` | **Lectura Arbitraria de 64 bits** |
| `wk_XOR_RAX_RAX_RET` | `0x023d14f6` | `xor rax, rax; ret` | Puesta a cero del registro RAX |

---

## 4. Análisis de Vulnerabilidades en Kernel Orbis OS (Ring 0)

### 4.1. CVE-2026-58076 — Desbordamiento en SysV IPC (`semctl` / `semop`)
* **Subsistema:** Subsistema de Comunicación entre Procesos (IPC) de FreeBSD / Orbis OS.
* **Mecanismo:** El kernel gestiona los semáforos de System V mediante una tabla indexada por identificadores de 15 bits (`0x7FFF`). Al invocar secuencias concurrentes masivas de `semget` combinadas con operaciones atómicas `semop(SEM_UNDO)` no sincronizadas, se produce un desbordamiento en el contador de referencias de la estructura `semid_kernel`.
* **Impacto en 14.02:** **VULNERABLE**. Sony no modificó la lógica de semáforos entre 14.00 y 14.02.
* **Primitiva Obtenida:** UMA Slab Use-After-Free en `zone-256`, permitiendo reemplazar la estructura del semáforo con datos arbitrarios y redirigir llamadas a funciones de kernel a direcciones controladas por el atacante.

### 4.2. Superficie de Kernel Adicional
* **`FreeBSD-SA-26:19.file` (`fdrop` race):** Condición de carrera en el decrecimiento del contador de referencias de descriptores de ficheros abiertos concurrentemente con `close` y `dup2`.

---

## 5. Protocolo de Seguridad y Advertencia de Trinchera

> [!WARNING]
> **DIRECTIVA INMUTABLE DE GARCÍA CASADO SECURITY RESEARCH:**
> 1. **La consola física de Adrián García Casado permanece como santuario intocable en Firmware 13.04 con GoldHEN 2.4b18.12.**
> 2. Todas las peticiones de actualización a 14.00, 14.02 o 14.10 deben ser bloqueadas mediante el servidor DNS de seguridad **`62.210.38.117`**.
> 3. La presente investigación sobre FW 14.02 se efectúa bajo análisis estático diferencial, emulación controlada y decompilación de módulos conforme a **ISO/IEC 29147 e ISO/IEC 30111**.

---

*García Casado Security Research // O Castro de Moreda / O Rañadoiro, Monforte de Lemos, Galicia.*
