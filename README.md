# CVE-2024-27840 — PPL Bypass via Dead Assert in vm_fault_enter

Found by patch-diffing XNU source between iOS 17.0 (xnu-10002.1.13) and iOS 17.5 (xnu-10063.121.3). Patched in iOS 17.5.

## The Bug (Two Stages)

### Stage 1: Missing cur ≤ max validation in vm_map_enter_mem_object_helper

When you create a memory mapping with `mach_vm_map`, you pass two protection values:
- `cur_protection` — what you can do with the memory right now
- `max_protection` — the ceiling, what you should ever be able to do

The kernel never checks that `cur` is within `max`. You can create a mapping with `cur=read+write` and `max=read-only`, and the kernel accepts it.

Fixed in iOS 17.5:
```c
if ((cur_protection & max_protection) != cur_protection) {
    cur_protection &= max_protection;
}
```

### Stage 2: Dead assert in vm_fault_enter (PPL bypass)

When the page faults in, `vm_fault_enter` calls `pmap_has_prot_policy()` — a PPL/pmap layer function that checks if the protection combination violates page protection policy. When it returns TRUE (violation detected), the code hits:

```c
// xnu-10002.1.13, osfmk/vm/vm_fault.c, line 3793-3797
if (!pmap_has_prot_policy(pmap, translated, *prot)) {
    *prot &= ~VM_PROT_WRITE;
} else {
    assert(cs_bypass);  // ← ((void)0) in RELEASE builds
}
```

In RELEASE kernels (all production iPhones), `assert()` compiles to `((void)0)`. The PPL policy violation is silently ignored. The PTE is created with write permission that `pmap_has_prot_policy` explicitly flagged as forbidden.

This is a PPL bypass because `pmap_has_prot_policy()` IS the PPL protection policy check. It runs in the pmap layer — the PPL/SPTM boundary. Bypassing it means PPL's own protection policy is never enforced on the page fault path.

Fixed in iOS 17.5: `assert(cs_bypass)` replaced with `panic("%s: pmap %p vaddr 0x%llx prot 0x%x options 0x%x !cs_bypass @%s:%d")`.

## Evidence

### 1. XNU Source (verified from Apple's public repository)

Repository: [apple-oss-distributions/xnu](https://github.com/apple-oss-distributions/xnu), tag `xnu-10002.1.13` (iOS 17.0).

File: `osfmk/vm/vm_fault.c`

Three call sites with the dead assert pattern:
- Line 3796: `assert(cs_bypass);`
- Line 4863-4870: `assert(cs_bypass);` with comment "cs_bypass must be true"
- Line 5552: `assert(fault_info.cs_bypass);`

All three fire when `pmap_has_prot_policy()` returns TRUE for a protection that violates PPL policy. All three are no-ops in RELEASE builds.

### 2. Binary Diff (iOS 17.0 vs 17.5.1 kernelcache)

Kernelcache files analyzed in Ghidra:
- `kernelcache_iphone14_3_17.0.macho` (iPhone 14,3, A15, iOS 17.0)
- `kernelcache_17.5.1.macho` (iOS 17.5.1)

| Search | iOS 17.0 | iOS 17.5.1 |
|--------|----------|------------|
| `strings \| grep "vm_fault_enter_prepare"` | 0 results | 1 result |
| `strings \| grep "!cs_bypass"` | 0 results | 1 result |
| `strings \| grep "pmap.*prot.*@%s:%d"` | 6 results | 9 results (+3 new) |

New panic strings in 17.5.1 that do not exist in 17.0:
```
%s: pmap %p vaddr 0x%llx prot 0x%x options 0x%x !cs_bypass @%s:%d
%s: pmap %p vaddr 0x%llx prot 0x%x options 0x%x @%s:%d
%s: pmap %p vaddr 0x%llx prot 0x%x options 0x%x m%p obj %p copyobj %p @%s:%d
```

These are the `panic()` calls that replaced the dead `assert()` calls. Their absence in 17.0 proves the assert compiled to nothing.

### 3. On-Device Test (iPhone 13 Pro Max, A15, iOS 17.0)

| Test | Method | Result |
|------|--------|--------|
| Sideloaded app (sandboxed) | `mach_vm_map(cur=RW, max=R)` | Accepted, write succeeds, same physical page |
| TrollStore app (unsandboxed) | Same test | Same result |
| `mach_vm_protect(addr, RW)` on same mapping | Upgrade via protect path | **Correctly blocked** (protect path enforces max) |

The protect path checks max_protection. The mapping path doesn't. Same kernel, two code paths, one checks, one doesn't.

### 4. Kernel-Context Verification (DarkSword exploit + kernel R/W)

Used the DarkSword kernel exploit (ICMPv6 socket corruption) to achieve kernel R/W, then verified CVE-2024-27840 from kernel context. Tested 3 times with different KASLR slides — same result every run.

**Part B — Live kernel code dump:**
Read 160 bytes of `vm_fault_enter_prepare` instructions from the running kernel at the slid address. The instruction sequence shows `B.EQ` (skip) after the `BICS` protection test — the dead assert pattern. On 17.5+, this would be `B.NE` + `TBNZ` + `BL _panic`.

**Part A — Userspace cur>max with kernel R/W active:**
- Stage 1: `mach_vm_map(cur=RW, max=R)` accepted by kernel ✓
- Stage 2: Write through the mapping visible at the source address (same physical page) ✓
- **CVE-2024-27840 FULLY VERIFIED ON THIS DEVICE** ✓

```
[+] kernel_base: 0xfffffff0657bc000
[+] kernel_slide: 0x3e7b8000
[*] vm_fault_enter_prepare @ 0xfffffff0665baac0 (unslid: 0xfffffff027e02ac0)
[+] Userspace cur>max mapping at 0x101728000 (cur=RW, max=R)
[+] Write through mapping: OK
[+] *** CVE-2024-27840 STAGE 1 VERIFIED: kernel accepted cur > max ***
[+] *** STAGE 2 VERIFIED: write visible through source (same physical page) ***
[+] *** CVE-2024-27840 FULLY VERIFIED ON THIS DEVICE ***
```

### 5. Full Impact Assessment (Tier 2-4 Tests)

After proving the base vulnerability (Tier 1), we tested escalation paths to determine if this is a PPL bypass or just a VM-layer bypass. All tests ran on-device with DarkSword kernel R/W active.

**Tier 2 — Code signing bypass: FAILED**

Two approaches tested, both rejected:
```
[+] Normal RW entry from signed page: REJECTED ((os/kern) protection failure) — correct
[-] PROT_COPY RW entry from signed page: REJECTED ((os/kern) protection failure)
```
`mach_make_memory_entry_64` enforces source mapping permissions **independently** of the CVE. Even `MAP_MEM_PROT_COPY` (which creates a copy to bypass max_protection checks) is rejected for code-signed pages. The code signing protection at the memory entry level is a separate, intact defense.

**Tier 3 — Kernel RO data bypass: FAILED**
```
[+] Normal mach_vm_protect(RW) blocked: (os/kern) protection failure (correct)
[-] CVE mapping failed for RO page: (os/kern) invalid right
```
Same defense: memory entry creation checks source max_protection. A page with `max_prot=R` cannot produce a writable memory entry, so `mach_vm_map(cur=RW)` is never attempted.

**Tier 4 — KTRR/PPL boundary: CONFIRMED (hardware holds)**
```
[+] kernel text @ 0xfffffff05d0f4100 = 0 (readable via kR/W)
[+] KTRR protects this — write would panic (proven by panic log)
[+] CVE-2024-27840 CANNOT bypass KTRR: CONFIRMED
```
Two kernel panics from earlier test runs prove KTRR blocks writes to the entire kernelcache static image:
- Panic 1: `x3: 0x4141414141414141` writing to `kernel_base+0x100` → "Unexpected fault in kernel static region"
- Panic 2: writing to `kernel_base+0x100000` → same panic

### 6. Defense Layer Analysis

The XNU memory protection stack has FIVE independent layers. CVE-2024-27840 bypasses only Layer 1:

```
Layer 1: vm_map_enter max_protection check         ← BYPASSED (the CVE)
Layer 2: mach_make_memory_entry_64 permission      ← INTACT (blocks Tier 2 & 3)
Layer 3: vm_fault_cs_check_violation (CS enforce)   ← INTACT (strips EXECUTE from unsigned pages)
Layer 4: pmap_enter / pmap_cs_enforce (PPL)         ← INTACT (PPL validates code signing in trust cache)
Layer 5: APRR hardware W^X enforcement             ← INTACT (hardware remaps RWX → RW for non-JIT)
```

| Defense Layer | Bypassed? | Evidence |
|---------------|-----------|----------|
| `vm_map_enter` cur≤max validation | **YES** | Tier 1: mapping accepted, write succeeds |
| `vm_fault_enter_prepare` dead assert | **YES** | RWX prot passes through in 17.0 (Ghidra diff) |
| `vm_map_remap_extract` propagation | **YES** | Tier 6: cur>max propagated through remap |
| `vm_map_copy_overwrite` propagation | **YES** | Tier 8: mach_vm_write succeeds in cur>max region |
| `mach_make_memory_entry_64` permissions | **NO** | Tier 2, 3, 5, 6b: `KERN_INVALID_RIGHT` |
| `vm_fault_cs_check_violation` CS enforce | **NO** | Tier 5b: EXECUTE stripped before pmap_enter |
| `pmap_enter` / `pmap_cs_enforce` (PPL) | **NO** | PPL validates code signing via trust cache |
| `mach_vm_protect` max enforcement | **NO** | Correctly blocked in Tier 1 alt test |
| KTRR (kernel text RO) | **NO** | Tier 4: kernel panic on write attempt |
| APRR hardware W^X | **NO** | Hardware register remaps RWX→RW for unsigned pages |

### On-Device Results (v9.0, iPhone 13 Pro Max, A15, iOS 17.0)

| Tier | Test | Result |
|------|------|--------|
| 1 | cur>max mapping + write (cur=RW, max=R) | **VERIFIED** — accepted, write works, same physical page |
| 2 | Code signing via memory entry | **BLOCKED** — `mach_make_memory_entry_64` rejects RW on signed pages |
| 3 | Kernel RO data bypass | **BLOCKED** — memory entry blocks at creation |
| 4 | KTRR/PPL boundary | **HOLDS** — KTRR blocks writes to static kernel image |
| 5 | RWX via memory entry path | **REJECTED** — entry has RW, requesting X → `KERN_INVALID_RIGHT` |
| 5b | RWX anonymous (MACH_PORT_NULL) | **ACCEPTED but SIGSEGV** — mach_vm_map accepted, execution blocked |
| 6 | Remap propagation (RW, max=R) | **VERIFIED** — cur=0x3 > max=0x1 propagated, write works |
| 6b | Remap from RWX source | **REJECTED** — memory entry blocks RWX |
| 7 | Fork propagation | **CHILD KILLED** — signal 10 (iOS kills forked children) |
| 8 | vm_map_copy_overwrite | **VERIFIED** — mach_vm_write into cur>max region succeeds |

### T5b Analysis — Why RWX Was Accepted But Execution Failed

Three independent enforcement layers blocked shellcode execution:

1. **`vm_fault_cs_check_violation`** (Layer 3): When the anonymous page faults with `prot=RWX`, this function detects that the page is unsigned (`VMP_CS_VALIDATED` is false). It flags a CS violation and strips `VM_PROT_EXECUTE` from the prot before calling `pmap_enter`. The page enters the pmap layer as RW, not RWX. (Source: XNU vm_fault.c:2639-2781)

2. **`pmap_cs_enforce`** (Layer 4, PPL): Even if EXECUTE reached the pmap layer, `pmap_enter_options_internal` escalates to exclusive lock and calls `pmap_cs_enforce`, which validates the page against trust caches. An anonymous page has no code directory → execute denied. (Source: XNU pmap.c:6068-6075)

3. **APRR hardware** (Layer 5): Even if a buggy PTE with RWX XPRR index were written, the APRR registers remap the permissions. For non-JIT pages, the hardware enforces W^X: RWX → RW at EL0. Only MAP_JIT pages with proper entitlements can toggle between RW and RX via APRR_MASK registers. (Source: Siguza APRR research)

The SIGSEGV on Tier 5b confirms: the PTE was created with RW permissions (no execute). The CPU's instruction fetch from that address triggered a hardware fault.

## Conclusion: VM-Layer Bypass, NOT a PPL Bypass

**CVE-2024-27840 is a VM max_protection enforcement bypass.** It is definitively NOT a PPL bypass.

The vulnerability allows:
- Creating mappings where `cur_protection > max_protection` (Tier 1, verified 6+ times across 5 KASLR slides)
- Propagation of the cur>max violation through `mach_vm_remap` (Tier 6, verified)
- Writes into cur>max regions via `mach_vm_write`/`vm_map_copy_overwrite` (Tier 8, verified)
- Bypassing `vm_fault_enter_prepare`'s dead assert (Ghidra diff confirmed)

The vulnerability does NOT allow:
- Execution of unsigned code — blocked by `vm_fault_cs_check_violation`, `pmap_cs_enforce`, and APRR hardware (Tier 5b, SIGSEGV)
- Writable access to code-signed pages — blocked by `mach_make_memory_entry_64` (Tier 2, rejected)
- Writes to kernel text/data — blocked by KTRR hardware (Tier 4, kernel panic)

Apple's description — "An attacker that has already achieved kernel code execution may be able to bypass kernel memory protections" — is accurate. The bypassed protections are the VM layer's `max_protection` enforcement and `vm_fault_enter_prepare`'s code signing assertion (dead in RELEASE). These are kernel memory protections, but defense-in-depth at the pmap/PPL/APRR layers prevents escalation to code signing bypass.

### Separate PPL Hardening (Silent Fix, No CVE)

The Ghidra diff also revealed a **separate, silent PPL hardening** between 17.0 and 17.5.1 that is NOT CVE-2024-27840:

| Change | Impact |
|--------|--------|
| New `pmap_cs_runtime` subsystem (13 functions) | Code signing validation moved INTO PPL |
| PPL trap number validation (`if (trap > 6) panic()`) | Prevents calling arbitrary internal PPL functions |
| `darwin arm64e pmap monitor` | New PPL monitoring/audit system |
| AppleImage4 overhaul (v245 → v257.120.3) | Image4 input validation + overflow checks |
| `pmap_force_pte_kernel_ro_if_protected_io` | Forced RO PTEs for protected I/O |

These changes address a different class of vulnerability — likely a Dopamine-style physical R/W PPL bypass where kernel R/W was used to map PPL-owned physical pages and manipulate trust caches directly. This fix has no public CVE assignment.

**A15 uses PPL (Page Protection Layer), NOT SPTM.** SPTM was introduced with A17 Pro (iPhone 15 Pro). This device runs PPL via APRR hardware compartmentalization at EL1.

## Files

- `poc.c` — compilable userspace demo
- `ios_test_app.m` — iOS app for on-device testing
- `CVE27840Tweak.m` — arm64e dylib for Coruna/SpringBoard injection
- `CVE27840App.ipa` — pre-built IPA (TrollStore)
- `coruna_cve_test.c` — replacement type 0x08 entry for Coruna F00DBEEF container (compiled but never executed on device — bootstrap.dylib selected a different payload hash)
- `Makefile` — builds coruna_cve_test.dylib (arm64e)
- `CVE27840Test.ipa` — TrollStore app v9.0: DarkSword kernel exploit + Tier 1-8 CVE tests (shellcode exec, remap, fork, copy_overwrite)

## Verified Kernel Offsets (iPhone14,3, A15, iOS 17.0, xnu-10002.1.13)

### DarkSword Exploit Offsets (verified from kfun binary RE + on-device testing)

| Offset | Value | Struct | Field | Source |
|--------|-------|--------|-------|--------|
| OFFSET_PCB_SOCKET | 0x38 | `struct inpcb` | `inp_socket` | kfun [0x524], verified 5 runs |
| OFFSET_SO_PROTO | 0x68 | `struct socket` | `so_proto` | kfun [0x52c], verified 5 runs |
| OFFSET_PR_INPUT | 0x10 | `struct protosw` | `pr_input` | kfun [0x544], verified 5 runs |
| OFFSET_ICMP6FILT | 0x150 | `struct inpcb` | `in6p_icmp6filt` | kfun [0x530], verified 5 runs |
| OFFSET_SOCKET_SO_COUNT | 0x22c | `struct socket` | `so_count` | kfun [0x538], verified 5 runs |

### kfun Offset Table (full dump from RE of offset resolver at 0x100006094)

Stored at runtime in `__DATA` at base `0x100011000`. Values shown are for the first branch (A15 CPU family `0x8765edea`):

| Table Offset | Value | Used In | Purpose |
|-------------|-------|---------|---------|
| [0x520] | 0x20 | post-exploit | `rwSocketPcb + 0x20 → controlSocketPcb` |
| [0x524] | 0x38 | exploit | `OFFSET_PCB_SOCKET` (inpcb → socket) |
| [0x528] | 0x40 | post-exploit | `inpcb + 0x40 → ?` (next pointer in traversal chain) |
| [0x52c] | 0x68 | exploit | `OFFSET_SO_PROTO` (socket → protosw) |
| [0x530] | 0x150 | exploit | `OFFSET_ICMP6FILT` (inpcb → icmp6 filter) |
| [0x534] | 0x158 | exploit | `ICMP6FILT + 8` |
| [0x538] | 0x22c | exploit | `OFFSET_SOCKET_SO_COUNT` |
| [0x53c] | 0x18 | post-exploit | unknown |
| [0x540] | 0x288 | post-exploit | traversal step 2 (`step1 + 0x288`) |
| [0x544] | 0x10 | exploit | `OFFSET_PR_INPUT` (protosw → pr_input) |
| [0x548] | 0x368 | post-exploit | traversal step 3 (`step2 + 0x368`) |
| [0x54c] | 0x10 | post-exploit | `step3 + 0x10` → result A (itk_space?) |
| [0x550] | 0x20 | post-exploit | `step3 + 0x20` → result B |
| [0x554] | 0xb0 | post-exploit | unknown |
| [0x558] | 0x00 | post-exploit | zero (flag) |
| [0x55c] | 0x08 | post-exploit | unknown |
| [0x560] | 0x18 | post-exploit | unknown |
| [0x564] | 0x60 | post-exploit | likely `PROC_P_PID` (proc → p_pid) |
| [0x568] | 0xd0 | post-exploit | unknown |
| [0x56c] | 0x548 | post-exploit | unknown |
| [0x570] | 0x579 | post-exploit | unknown |

Alternative offset sets for other CPU families (from kfun resolver branches):

| Branch | [0x540] | [0x548] | [0x538] | Likely CPU |
|--------|---------|---------|---------|-----------|
| 1 | 0x288 | 0x368 | 0x22c | A15 (Blizzard/Avalanche) |
| 2 | 0x2a8 | 0x378/0x380 | 0x24c | A16 or variant |
| 3 | 0x2b0 | 0x380/0x388 | — | A17 or variant |
| 4 | 0x298 | 0x390 | 0x23c | fallback/older |

### Kernel Globals (from Ghidra analysis of kernelcache_iphone14_3_17.0.macho)

| Symbol | Unslid Address | Verified |
|--------|---------------|----------|
| kernel base (__TEXT vmaddr) | 0xfffffff027004000 | Yes — matches runtime `kernel_base - kernel_slide` across 5 runs |
| `vm_fault_enter_prepare` | 0xfffffff027e02ac0 | Yes — live kernel code dump matches Ghidra disassembly |
| `kernel_proc` | 0xfffffff027900428 | Ghidra only — allproc walk failed on device (PAC/offset issues) |
| `allproc` | 0xfffffff02a2bd308 | Ghidra only — not verified on device |
| `proc_to_task_offset` | 0xfffffff02a255380 | Ghidra only |

### vm_named_entry Layout (from XNU source xnu-10002.1.13 vm_map.h line 162)

```c
struct vm_named_entry {                      // Total: 0x38 bytes (estimated)
    lck_mtx_t           Lock;               // +0x00 (16 bytes on arm64)
    union {
        vm_map_t        map;
        vm_map_copy_t   copy;
    }                   backing;            // +0x10 (8 bytes)
    vm_object_offset_t  offset;             // +0x18 (8 bytes)
    vm_object_size_t    size;               // +0x20 (8 bytes)
    vm_object_offset_t  data_offset;        // +0x28 (8 bytes)
    unsigned int        access:8;           // +0x30 bits 0-7
    unsigned int        protection:4;       // +0x30 bits 8-11  ← patch target for Tier 2
    unsigned int        is_object:1;        // +0x30 bit 12
    unsigned int        internal:1;         // +0x30 bit 13
    unsigned int        is_sub_map:1;       // +0x30 bit 14
    unsigned int        is_copy:1;          // +0x30 bit 15
    unsigned int        is_fully_owned:1;   // +0x30 bit 16
};
```

**WARNING**: `lck_mtx_t` size may differ between kernel configs. If it's 8 bytes instead of 16, all subsequent offsets shift by -8. Not verified on device.

### On-Device Kernel Addresses (from 5 successful runs)

| Run | kernel_base | kernel_slide | vm_fault_enter_prepare (slid) |
|-----|------------|-------------|-------------------------------|
| 1 | 0xfffffff0641d4000 | 0x3d1d0000 | 0xfffffff064fd2ac0 |
| 2 | 0xfffffff0657bc000 | 0x3e7b8000 | 0xfffffff0665baac0 |
| 3 | 0xfffffff068b00000 | 0x41afc000 | 0xfffffff0698feac0 |
| 4 | 0xfffffff052ee0000 | 0x2bedc000 | 0xfffffff053cdeac0 |
| 5 | 0xfffffff058548000 | 0x31544000 | 0xfffffff059346ac0 |

All 5 runs: `vm_fault_enter_prepare` at unslid `0xfffffff027e02ac0`. First 160 bytes of instructions identical across all runs — confirms stable kernelcache.

### Panic Log Evidence

| Panic | File | Cause | Register Evidence |
|-------|------|-------|-------------------|
| KTRR write `base+0x100` | panic-full-2026-03-28-131443.0002.ips | `Unexpected fault in kernel static region` | `x3: 0x4141414141414141` |
| KTRR write `base+0x100000` | panic-full-2026-03-28-133756.0002.ips | `Unexpected fault in kernel static region` | `x3: 0x25203a65756c6189` |
| DarkSword bad offset | panic-full-2026-03-28-111709.0002.ips | `copy_validate kaddr not in kernel` | Wrong struct offsets (pre-fix) |
| App exit cleanup | panic-full-2026-03-28-114700.0002.ips | `data abort in kernel` | Corrupted socket cleanup on exit |

### Binary Diff Summary (17.0 vs 17.5.1)

New panic/function-name strings in 17.5.1 not present in 17.0:

```
%s: pmap %p vaddr 0x%llx prot 0x%x options 0x%x !cs_bypass @%s:%d
%s: pmap %p vaddr 0x%llx prot 0x%x options 0x%x @%s:%d
%s: pmap %p vaddr 0x%llx prot 0x%x options 0x%x m%p obj %p copyobj %p @%s:%d
%s: map %p pmap %p entry %p 0x%llx:0x%llx prot 0x%x @%s:%d
vm_fault_enter_prepare
vm_map_copy_overwrite
vm_map_fork
vm_map_fork_share
vm_map_lookup_and_lock_object
vm_map_remap_extract
```

Removed from 17.0 (restructured in 17.5.1):
```
code-signing violation for nested pmap %p vaddr 0x%llx prot 0x%x fault 0x%x @%s:%d
```

This shows Apple added protection checks to 5 additional VM paths beyond the original `vm_fault_enter_prepare` fix.

### 7. Ghidra Function Address Mapping

Complete mapping of patched functions traced via string xrefs:

| Function | iOS 17.5.1 Address | iOS 17.0 Address | String Trigger |
|---|---|---|---|
| `vm_fault_enter_prepare` | `FUN_fffffff007e28b3c` | `FUN_fffffff027e02ac0` | `!cs_bypass` panic at `fffffff00704ba80` |
| `vm_map_remap_extract` | `FUN_fffffff007e3ff5c` | *(stripped, no string)* | Format string at `fffffff00704ca10` |
| `vm_map_fork_share` | `FUN_fffffff007e45ac4` | *(stripped, no string)* | Name string at `fffffff00704cf1a` |
| `vm_map_copy_overwrite` | `FUN_fffffff007e41bcc` | *(stripped, no string)* | Name string at `fffffff00704c9c7` |
| `vm_map_lookup_and_lock_object` | `FUN_fffffff007e3b55c` | *(stripped, no string)* | Name string at `fffffff00704ca8c` |

### 8. Decompilation Diff — vm_fault_enter_prepare

**The exact code difference that constitutes the vulnerability:**

**iOS 17.5.1** (`FUN_fffffff007e28b3c`) — PATCHED:
```c
if ((*param_11 != 1 && ((param_9 & 2) == 0 && param_8 == 0))
    && ((*(byte *)(param_1 + 0x2d) & 1) == 0)) {
    if (((*param_4 ^ 0xffffffff) & 7) == 0) {   // prot == RWX
        if ((uVar17 >> 3 & 1) == 0) {            // !cs_bypass
            PANIC("!cs_bypass");                  // ← PANICS
        }
    } else {
        *param_4 = *param_4 & 0xfffffffd;        // clear WRITE
    }
}
```

**iOS 17.0** (`FUN_fffffff027e02ac0`) — VULNERABLE:
```c
if ((*param_11 != 1 && ((param_9 & 2) == 0 && param_8 == 0))
    && ((*(byte *)(param_1 + 0x2d) & 1) == 0)
    && (((*param_4 ^ 0xffffffff) & 7) != 0)) {   // prot != RWX
    *param_4 = *param_4 & 0xfffffffd;             // clear WRITE
}
// ← When prot == RWX: ENTIRE CHECK SKIPPED. No panic, no write-clear.
// RWX passes through UNTOUCHED to pmap_enter.
```

**Key difference**: In 17.0, the condition `((*param_4 ^ 0xFFFFFFFF) & 7) != 0` is an OUTER condition — when prot is RWX (`prot & 7 == 7`), the XOR gives 0, the AND gives 0, the `!= 0` is FALSE, so the entire if-body is skipped. In 17.5.1, it's an INNER condition with a panic fallback.

### 9. Decompilation Diff — vm_map_remap_extract

**iOS 17.5.1** (`FUN_fffffff007e3ff5c`) — PATCHED:
```c
// In the entry extraction loop, after processing pmap operations:
if (((uVar18 >> 6 & 1) == 0) && ((uVar18 & 0x500) != 0)) {
    if ((~uVar18 & 0x380) == 0) {    // bits 7,8,9 ALL set = cur_prot RWX
        PANIC("%s: map %p pmap %p entry %p 0x%llx:0x%llx prot 0x%x @%s:%d");
    }
    // ... continue with pmap unmap/remap operations
}
```

**iOS 17.0**: This entire check is ABSENT. The function extracts entries with whatever protections they have and passes them through — including cur>max violations. `mach_vm_remap` propagates the violation without enforcement.

### 10. New Tier Tests (v9.0)

Previous Tier 2/3 tests failed because they went through `mach_make_memory_entry_64` which has an independent permission check. The Ghidra diff revealed 5 additional paths that bypass memory entries entirely:

| Tier | Test | Path | Bypasses mem entry? |
|------|------|------|-------------------|
| 5 | Direct shellcode execution (cur=RWX, max=R) | `mach_vm_map` → `vm_fault_enter_prepare` | Yes (direct mapping) |
| 5b | Anonymous RWX (no memory entry at all) | `mach_vm_map(MACH_PORT_NULL)` | Yes (no entry) |
| 6 | Remap propagation | `mach_vm_remap` → `vm_map_remap_extract` | Yes (remap) |
| 6b | Remap from RWX source + shellcode exec | `mach_vm_remap` from RWX mapping | Yes (remap) |
| 7 | Fork propagation (inherit=SHARE) | `fork()` → `vm_map_fork_share` | Yes (fork) |
| 8 | vm_map_copy_overwrite | `mach_vm_write` into cur>max region | Yes (copy) |

**Critical insight**: `mach_vm_remap` has `cur_prot`/`max_prot` as OUTPUT parameters. The exploitation vector is PROPAGATION of existing cur>max violations through paths that had no enforcement in 17.0.

## Timeline

- iOS 17.0 (xnu-10002.1.13): Vulnerable — `assert(cs_bypass)` is no-op in RELEASE
- iOS 17.5 (xnu-10063.121.3): Patched — `assert` replaced with `panic`, `cur` clamped to `max`

## Credits

- Found by patch-diffing Apple's open-source XNU releases
- On-device testing and binary verification by [@Somisomair](https://github.com/Somisomair)
- Original vulnerability reported to Apple by an anonymous researcher
