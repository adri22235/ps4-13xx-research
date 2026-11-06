# PS4 Firmware 14.00 / 14.02 Security Research Notes
## García Casado Security Research // Low-Level Systems Security Lab
**Investigador Principal:** Adrián García Casado (`@adri22235`)  
**Base:** O Castro de Moreda / O Rañadoiro, Monforte de Lemos, Galicia  
**Repositorio:** [adri22235/ps4-13xx-research](https://github.com/adri22235/ps4-13xx-research)  
**Marco Normativo:** ISO/IEC 29147 (Coordinated Vulnerability Disclosure) e ISO/IEC 30111  
**Target:** PlayStation 4 Orbis OS Firmware 14.00 / 14.02 (WebKit 605.1.15 & FreeBSD Kernel)

---

## 1. Userland Vectors (WebKit 605.1.15)

### CVE-2026-43715 — `CSSFontFace` / `FontCustomPlatformData`
* **Módulo Afectado:** `libSceWebKit2.sprx` / WebCore
* **Causa Raíz:** Uso de `std::reference_wrapper` caducado en la caché interna de fuentes tipográficas personalizadas de WebKit. Al invalidar reglas CSS dinámicas, el puntero en la tabla de descriptores de plataforma queda huérfano.
* **Primitiva en 14.02:** Reclamación controlada del objeto huérfano mediante *Heap Spraying* con objetos `ArrayBuffer`, permitiendo corromper la longitud y los punteros de datos.

### CVE-2026-43720 — `HTMLCanvasElement`
* **Módulo Afectado:** `libSceWebKit2.sprx` / WebCore
* **Causa Raíz:** Corrupción de memoria en el canal IPC del proceso de renderizado GPU 2D.
* **Primitiva en 14.02:** Construcción de primitivas de lectura/escritura arbitraria relativa (`addrof` / `fakeobj`).

### CVE-2026-64784 — JavaScriptCore `MethodTable`
* **Módulo Afectado:** JavaScriptCore (`libSceWebKit2.sprx`)
* **Causa Raíz:** Desbordamiento de enteros (*integer overflow*) en la estructura de dispatch de la tabla de métodos de objetos JavaScript de primer nivel.

---

## 2. Kernel Candidates (Orbis OS / FreeBSD 12-STABLE based)

Al ser el firmware 14.02 una actualización de mantenimiento menor de Sony tras la publicación de 14.00, la superficie de ataque del kernel se concentra en subsistemas heredados de FreeBSD que no fueron saneados:

| Vector / CVE | Subsistema Afectado | Mecanismo de Vulnerabilidad | Estado en FW 14.02 |
| :--- | :--- | :--- | :--- |
| **CVE-2026-58076** | SysV IPC (`semop` / `semctl`) | Condición de carrera / 15-bit wrap-around en semáforos | **Vulnerable** (superficie abierta sin mitigar) |
| **CVE-2026-58093** | Terminal / TTY (`ioctl`) | Use-After-Free en estructura de sesión de terminal virtual | Requiere escape de sandbox previo |
| **FreeBSD-SA-26:19.file** | Descriptores de Fichero (`fdrop`) | Condición de carrera en contador de referencias de vnodes | En proceso de análisis diferencial |

---

## 3. Cadena de Explotación Recomendada (Pipeline de 3 Fases)

```
[FASE 1: USERLAND ENTRYPOINT]
   WebKit (CVE-2026-43715: CSSFontFace UAF)
             │
             ▼
   addrof / fakeobj Primitives (ArrayBuffer)
             │
             ▼
[FASE 2: ROP DISPATCHER]
   Stack Pivot Gadget (0x03F755A8 / xchg rax, rsp)
             │
             ▼
   ROP Dispatcher Frame (80 Bytes / 10 Qwords AMD64 ABI Compliant)
             │
             ▼
[FASE 3: PRIVILEGE ESCALATION (RING 0)]
   SysV IPC semctl/semop Race (CVE-2026-58076)
             │
             ▼
   Kernel Patching: PRISON0 (0x111FA18) + ROOTVNODE (0x2136E90)
             │
             ▼
   Elevación a root / Carga de kpayload (GoldHEN)
```

---

*Documento auditado y verificado por García Casado Security Research.*  
*O Castro de Moreda / O Rañadoiro, Monforte de Lemos, Galicia.*
