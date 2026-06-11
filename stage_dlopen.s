// Stage dlopen loader (multi-payload). Runs from an anonymous RWX mapping
// allocated by the stub. Per-payload gated protocol:
//   1) announce pid + status=1 in the mailbox, spin until the injector
//      releases gate>=1 (it has restored our setArgV0 page in the child by
//      then, so the BLR below lands on real code).
//   2) call the real setArgV0 ONCE with the original args.
//   3) for each payload i in 0..count-1:
//        - dlopen(path[i], RTLD_NOW, NULL)
//        - publish the handle, then unlink the staged copy from disk
//        - publish loaded=i+1, then spin until the injector acks gate>=i+2
//          (it has hidden the VMAs + unlinked the soinfo for payload i by
//          then, so it is safe to load the next one).
//   4) status=3, madvise the trap pages back to file-backed, return to caller.
//
// gate (injector-written) and loaded (stage-written) are monotonic counters:
// gate==1 releases the single setArgV0 call; gate==i+2 acks payload i. The
// handshake keeps the single handle slot stable — the stage never overwrites
// it for payload i+1 until the injector has acked payload i.

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
    str  x9, [x20, #16]      // status=1: announced, spinning for child restore
_spin_restore:
    ldr  x9, [x20, #24]      // gate from injector
    cbz  x9, _spin_restore   // wait gate>=1 (child setArgV0 page restored)

    // Call the real setArgV0 ONCE with the original args.
    ldr  x29, [sp, #128]
    ldr  x8, [sp, #32]
    ldp  x2, x3, [sp, #16]
    ldp  x0, x1, [sp]
    ldr  x9, _orig_hook_slot
    blr  x9

    // Per-payload loop. x21 = i, x22 = count.
    mov  x21, #0
    ldr  x22, _count
_lib_loop:
    cmp  x21, x22
    b.ge _libs_done
    adr  x23, _payload_paths
    add  x23, x23, x21, lsl #7   // path[i] = _payload_paths + i*128

    // dlopen(path[i], RTLD_NOW, NULL).
    mov  x0, x23
    mov  x1, #2
    mov  x2, xzr
    ldr  x8, _dlopen_slot
    blr  x8
    str  x0, [x20]          // handle (0 on failure)

    // Unlink the staged copy from disk if dlopen succeeded. The kernel keeps
    // the inode alive via the now-mapped segments.
    cbz  x0, _skip_unlink
    mov  x0, #-100          // AT_FDCWD
    mov  x1, x23
    mov  x2, xzr
    mov  x8, #35            // unlinkat
    svc  #0
_skip_unlink:

    // Publish loaded=i+1, then wait for the injector to ack gate>=i+2.
    add  x9, x21, #1
    str  x9, [x20, #32]     // loaded
    add  x24, x21, #2       // need gate>=i+2
_wait_ack:
    ldr  x9, [x20, #24]
    cmp  x9, x24
    b.lt _wait_ack

    add  x21, x21, #1
    b    _lib_loop
_libs_done:

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
    // before hiding the stage VMA.
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

.balign 8
_dlopen_slot:
    .8byte 0
_orig_hook_slot:
    .8byte 0
_count:
    .8byte 0
_mailbox:
    .space 48, 0x00
_payload_paths:
    .space 128 * 16, 0x00

    .space 4096 - (. - _start), 0x00
