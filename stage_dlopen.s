// Stage dlopen loader. Runs from an anonymous RWX mapping allocated by the
// stub. Three-phase protocol:
//   1) announce pid + status=1 in the mailbox, spin for the injector
//   2) call the real setArgV0 (whose original bytes the injector restored
//      in the child while we were spinning), then call __loader_dlopen
//   3) write the dlopen handle + status=2, unlink the staged payload from
//      disk, madvise the trap pages back to file-backed, return to caller.

.text
.global _start
_start:
    sub  sp, sp, #192
    stp  x0, x1, [sp]
    stp  x2, x3, [sp, #16]
    str  x8, [sp, #32]
    str  x30, [sp, #40]
    stp  x19, x20, [sp, #48]
    stp  x21, x22, [sp, #64]
    stp  x23, x24, [sp, #80]
    stp  x25, x26, [sp, #96]
    str  x27, [sp, #112]
    str  x28, [sp, #120]
    str  x29, [sp, #128]

    adr  x20, _mailbox
    mov  x8, #172            // getpid
    svc  #0
    str  x0, [x20, #8]
    mov  x9, #1
    str  x9, [x20, #16]      // status: ready for child text restore
_spin_restore:
    ldr  x9, [x20, #24]      // release flag from injector
    cbz  x9, _spin_restore

    // Call the real setArgV0 with the original args.
    ldr  x29, [sp, #128]
    ldr  x8, [sp, #32]
    ldp  x2, x3, [sp, #16]
    ldp  x0, x1, [sp]
    ldr  x9, _orig_hook_slot
    blr  x9

    // dlopen(payload_path, RTLD_NOW, NULL).
    adr  x0, _payload_path
    mov  x1, #2
    mov  x2, xzr
    ldr  x8, _dlopen_slot
    blr  x8
    mov  x19, x0
    str  x19, [x20]          // handle (0 on failure)
    mov  x9, #2
    str  x9, [x20, #16]      // status: dlopen returned

    // Unlink the staged copy from disk if dlopen succeeded. Kernel keeps the
    // inode alive via the now-mapped segments.
    cbz  x19, _skip_unlink
    mov  x0, #-100           // AT_FDCWD
    adr  x1, _payload_path
    mov  x2, xzr
    mov  x8, #35             // unlinkat
    svc  #0
_skip_unlink:

    // Drop the CoW'd setArgV0 pages so they revert to file-backed page-cache.
    // Erases the smaps Anonymous/Private_Dirty fingerprint left by trap
    // install + restore. setArgV0+428 crosses one 4 KB boundary so cover 8 KB.
    ldr  x0, _orig_hook_slot
    and  x0, x0, #0xfffffffffffff000
    mov  x1, #0x2000
    mov  x2, #4              // MADV_DONTNEED
    mov  x8, #233            // madvise
    svc  #0

    // Final status: 3 = stage done, about to RET. Injector waits for this
    // before tearing down the soinfo and hiding the stage VMA.
    mov  x9, #3
    str  x9, [x20, #16]

    ldr  x29, [sp, #128]
    ldr  x28, [sp, #120]
    ldr  x27, [sp, #112]
    ldp  x25, x26, [sp, #96]
    ldp  x23, x24, [sp, #80]
    ldp  x21, x22, [sp, #64]
    ldp  x19, x20, [sp, #48]
    ldr  x30, [sp, #40]
    ldr  x8, [sp, #32]
    ldp  x2, x3, [sp, #16]
    ldp  x0, x1, [sp]
    add  sp, sp, #192
    ret

_dlopen_slot:
    .8byte 0
_orig_hook_slot:
    .8byte 0
_payload_path:
    .space 128, 0x00
_mailbox:
    .space 32, 0x00

    .space 4096 - (. - _start), 0x00
