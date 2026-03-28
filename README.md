# XNU vm_map cur>max Protection Bug

Found by patch-diffing XNU source between iOS 17.4 (xnu-10063.101.15) and iOS 17.5 (xnu-10063.121.3).

We don't know which CVE it corresponds to. iOS 17.5 patched three kernel bugs (CVE-2024-27818, CVE-2024-27840, CVE-2024-27843). This could be any of them.

## The Bug

When you create a memory mapping with `mach_vm_map`, you pass two protection values:
- `cur_protection` — what you can do with the memory right now
- `max_protection` — the ceiling, what you should ever be able to do

The kernel never checks that `cur` is actually within `max`. You can create a mapping with `cur=read+write` and `max=read-only`, and the kernel accepts it. The write works.

Apple fixed this in iOS 17.5 by clamping `cur` to `max`:
```c
if ((cur_protection & max_protection) != cur_protection) {
    cur_protection &= max_protection;
}
```

## What We Tested

We built an iOS app that creates a mapping with `cur=RW, max=R` and tries to write through it.

| Test | What | Result |
|---|---|---|
| Sideloaded app (sandboxed) | mach_vm_map(cur=RW, max=R) | Write works, same physical page |
| TrollStore app (unsandboxed) | Same test | Same result |
| Coruna chain + SpringBoard injection | Same test inside SpringBoard | Same result |
| mach_vm_protect(addr, RW) on same mapping | Try to upgrade via protect path | **Correctly blocked** |

The protect path enforces max_protection. The mapping path doesn't. Same bug, two different code paths, one checks, one doesn't.

Device: iPhone 13 Pro Max, A15, iOS 17.0 (21A329).

## What We Didn't Test

We only tested from userspace on our own process memory. We couldn't test from kernel context. We tried — the kernel exploit we had crashed the device, the kernel task port is blocked by multiple checks, and the exploit chain we used doesn't give persistent kernel access to injected code.

The function with the bug (vm_map_enter_mem_object_helper) is the same for both user and kernel maps. The missing check applies to both. But we only proved it works on user maps.

## Binary Verification

We checked the compiled kernelcache in Ghidra. There's a second part: vm_fault_enter_prepare had assert() calls that check protection policies. In release builds, assert() compiles to nothing. Apple fixed this by converting them to if/panic.

- iOS 17.0 kernelcache: zero panic strings for protection policy violations
- iOS 17.5.1 kernelcache: four new panic strings

The 17.0 kernel skips the protection check entirely. The 17.5.1 kernel panics if it fails.

## SPTM

The test device (A15) has SPTM. The bug still works because SPTM enforces page types, not max_protection.

## Files

- `poc.c` — compilable userspace demo
- `ios_test_app.m` — iOS app for on-device testing
- `CVE27840Tweak.m` — arm64e dylib for Coruna/SpringBoard injection
- `CVE27840App.ipa` — pre-built IPA (TrollStore)

## Credits

- Found by patch-diffing Apple's open-source XNU releases
- On-device testing and binary verification by [@Somisomair](https://github.com/Somisomair)
- Original vulnerability reported to Apple by an anonymous researcher
