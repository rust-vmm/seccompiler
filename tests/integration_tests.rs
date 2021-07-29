use std::collections::BTreeMap;

use seccompiler::SeccompCmpArgLen::*;
use seccompiler::SeccompCmpOp::*;
use seccompiler::{
    sock_filter, BpfProgram, SeccompAction, SeccompCondition as Cond, SeccompFilter, SeccompRule,
};
use std::convert::TryInto;
use std::env::consts::ARCH;
use std::thread;

// BPF structure definition for filter array.
// See /usr/include/linux/filter.h .
#[repr(C)]
struct sock_fprog {
    pub len: ::std::os::raw::c_ushort,
    pub filter: *const sock_filter,
}

// The type of the `req` parameter is different for the `musl` library. This will enable
// successful build for other non-musl libraries.
#[cfg(target_env = "musl")]
type IoctlRequest = i32;
#[cfg(not(target_env = "musl"))]
type IoctlRequest = u64;

// We use KVM_GET_PIT2 as the second parameter for ioctl syscalls in some unit tests
// because has non-0 MSB and LSB.
const KVM_GET_PIT2: u64 = 0x8070_ae9f;
const KVM_GET_PIT2_MSB: u64 = 0x0000_ae9f;
const KVM_GET_PIT2_LSB: u64 = 0x8070_0000;

const FAILURE_CODE: i32 = 1000;

const EXTRA_SYSCALLS: [i64; 6] = [
    libc::SYS_rt_sigprocmask,
    libc::SYS_sigaltstack,
    libc::SYS_munmap,
    libc::SYS_exit,
    libc::SYS_rt_sigreturn,
    libc::SYS_futex,
];

fn install_filter(bpf_filter: BpfProgram) {
    unsafe {
        {
            let rc = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            assert_eq!(rc, 0);
        }
        let bpf_prog = sock_fprog {
            len: bpf_filter.len() as u16,
            filter: bpf_filter.as_ptr(),
        };
        let bpf_prog_ptr = &bpf_prog as *const sock_fprog;
        {
            let rc = libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                bpf_prog_ptr,
            );
            assert_eq!(rc, 0);
        }
    }
}

fn validate_seccomp_filter(
    rules: Vec<(i64, Vec<SeccompRule>)>,
    validation_fn: fn(),
    should_fail: Option<bool>,
) {
    let mut rule_map: BTreeMap<i64, Vec<SeccompRule>> = rules.into_iter().collect();

    // Make sure the extra needed syscalls are allowed
    for syscall in EXTRA_SYSCALLS.iter() {
        rule_map.entry(*syscall).or_insert_with(std::vec::Vec::new);
    }

    // Build seccomp filter.
    let filter = SeccompFilter::new(
        rule_map,
        SeccompAction::Errno(FAILURE_CODE as u32),
        SeccompAction::Allow,
        ARCH.try_into().unwrap(),
    )
    .unwrap();

    let filter: BpfProgram = filter.try_into().unwrap();

    // We need to run the validation inside another thread in order to avoid setting
    // the seccomp filter for the entire unit tests process.
    let errno = thread::spawn(move || {
        // Install the filter.
        install_filter(filter);

        // Call the validation fn.
        validation_fn();

        // Return errno.
        std::io::Error::last_os_error().raw_os_error().unwrap()
    })
    .join()
    .unwrap();

    // In case of a seccomp denial `errno` should be `FAILURE_CODE`
    if let Some(should_fail) = should_fail {
        if should_fail {
            assert_eq!(errno, FAILURE_CODE);
        } else {
            assert_ne!(errno, FAILURE_CODE);
        }
    }
}

#[test]
fn test_empty_filter() {
    // An empty filter should always return the default action.
    // For example, for an empty allowlist, it should always trap/kill,
    // for an empty denylist, it should allow allow all system calls.

    let filter = SeccompFilter::new(
        BTreeMap::new(),
        SeccompAction::Allow,
        SeccompAction::Trap,
        ARCH.try_into().unwrap(),
    )
    .unwrap();
    let prog: BpfProgram = filter.try_into().unwrap();

    // This should allow any system calls.
    let pid = thread::spawn(move || {
        // Install the filter.
        install_filter(prog);

        unsafe { libc::getpid() }
    })
    .join()
    .unwrap();

    // Check that the getpid syscall returned successfully.
    assert!(pid > 0);
}

#[test]
fn test_invalid_architecture() {
    // A filter compiled for another architecture should kill the process upon evaluation.
    // The process will appear as if it received a SIGSYS.
    let mut arch = "aarch64";

    if ARCH == "aarch64" {
        arch = "x86_64";
    }

    let filter = SeccompFilter::new(
        BTreeMap::new(),
        SeccompAction::Allow,
        SeccompAction::Trap,
        arch.try_into().unwrap(),
    )
    .unwrap();
    let prog: BpfProgram = filter.try_into().unwrap();

    let pid = unsafe { libc::fork() };
    match pid {
        0 => {
            install_filter(prog);

            unsafe {
                libc::getpid();
            }
        }
        child_pid => {
            let mut child_status: i32 = -1;
            let pid_done = unsafe { libc::waitpid(child_pid, &mut child_status, 0) };
            assert_eq!(pid_done, child_pid);

            assert!(libc::WIFSIGNALED(child_status));
            assert_eq!(libc::WTERMSIG(child_status), libc::SIGSYS);
        }
    };
}

#[test]
fn test_eq_operator() {
    // check use cases for DWORD
    let rules = vec![(
        libc::SYS_ioctl,
        vec![SeccompRule::new(vec![Cond::new(1, Dword, Eq, KVM_GET_PIT2).unwrap()]).unwrap()],
    )];
    // check syscalls that are supposed to work
    validate_seccomp_filter(
        rules.clone(),
        || unsafe {
            libc::ioctl(0, KVM_GET_PIT2 as IoctlRequest);
        },
        Some(false),
    );
    // check syscalls that are not supposed to work
    validate_seccomp_filter(
        rules,
        || unsafe {
            libc::ioctl(0, 0);
        },
        Some(true),
    );

    // check use cases for QWORD
    let rules = vec![(
        libc::SYS_ioctl,
        vec![SeccompRule::new(vec![Cond::new(2, Qword, Eq, u64::MAX).unwrap()]).unwrap()],
    )];
    // check syscalls that are supposed to work
    validate_seccomp_filter(
        rules.clone(),
        || unsafe {
            libc::ioctl(0, 0, u64::MAX);
        },
        Some(false),
    );
    // check syscalls that are not supposed to work
    validate_seccomp_filter(
        rules,
        || unsafe {
            libc::ioctl(0, 0, 0);
        },
        Some(true),
    );
}

#[test]
fn test_ge_operator() {
    // check use case for DWORD
    let rules = vec![(
        libc::SYS_ioctl,
        vec![SeccompRule::new(vec![Cond::new(1, Dword, Ge, KVM_GET_PIT2).unwrap()]).unwrap()],
    )];
    // check syscalls that are supposed to work
    validate_seccomp_filter(
        rules.clone(),
        || unsafe {
            libc::ioctl(0, KVM_GET_PIT2 as IoctlRequest);
            libc::ioctl(0, (KVM_GET_PIT2 + 1) as IoctlRequest);
        },
        Some(false),
    );
    // check syscalls that are not supposed to work
    validate_seccomp_filter(
        rules,
        || unsafe {
            libc::ioctl(0, (KVM_GET_PIT2 - 1) as IoctlRequest);
        },
        Some(true),
    );

    // check use case for QWORD
    let rules = vec![(
        libc::SYS_ioctl,
        vec![SeccompRule::new(vec![
            Cond::new(2, Qword, Ge, u64::from(std::u32::MAX)).unwrap()
        ])
        .unwrap()],
    )];
    // check syscalls that are supposed to work
    validate_seccomp_filter(
        rules.clone(),
        || unsafe {
            libc::ioctl(0, 0, u64::from(std::u32::MAX));
            libc::ioctl(0, 0, u64::from(std::u32::MAX) + 1);
        },
        Some(false),
    );
    // check syscalls that are not supposed to work
    validate_seccomp_filter(
        rules,
        || unsafe {
            libc::ioctl(0, 0, 1);
        },
        Some(true),
    );
}

#[test]
fn test_gt_operator() {
    // check use case for DWORD
    let rules = vec![(
        libc::SYS_ioctl,
        vec![SeccompRule::new(vec![Cond::new(1, Dword, Gt, KVM_GET_PIT2).unwrap()]).unwrap()],
    )];
    // check syscalls that are supposed to work
    validate_seccomp_filter(
        rules.clone(),
        || unsafe {
            libc::ioctl(0, (KVM_GET_PIT2 + 1) as IoctlRequest);
        },
        Some(false),
    );
    // check syscalls that are not supposed to work
    validate_seccomp_filter(
        rules,
        || unsafe {
            libc::ioctl(0, KVM_GET_PIT2 as IoctlRequest);
        },
        Some(true),
    );

    // check use case for QWORD
    let rules = vec![(
        libc::SYS_ioctl,
        vec![SeccompRule::new(vec![
            Cond::new(2, Qword, Gt, u64::from(std::u32::MAX) + 10).unwrap()
        ])
        .unwrap()],
    )];
    // check syscalls that are supposed to work
    validate_seccomp_filter(
        rules.clone(),
        || unsafe {
            libc::ioctl(0, 0, u64::from(std::u32::MAX) + 11);
        },
        Some(false),
    );
    // check syscalls that are not supposed to work
    validate_seccomp_filter(
        rules,
        || unsafe {
            libc::ioctl(0, 0, u64::from(std::u32::MAX) + 10);
        },
        Some(true),
    );
}

#[test]
fn test_le_operator() {
    // check use case for DWORD
    let rules = vec![(
        libc::SYS_ioctl,
        vec![SeccompRule::new(vec![Cond::new(1, Dword, Le, KVM_GET_PIT2).unwrap()]).unwrap()],
    )];
    // check syscalls that are supposed to work
    validate_seccomp_filter(
        rules.clone(),
        || unsafe {
            libc::ioctl(0, KVM_GET_PIT2 as IoctlRequest);
            libc::ioctl(0, (KVM_GET_PIT2 - 1) as IoctlRequest);
        },
        Some(false),
    );
    // check syscalls that are not supposed to work
    validate_seccomp_filter(
        rules,
        || unsafe {
            libc::ioctl(0, (KVM_GET_PIT2 + 1) as IoctlRequest);
        },
        Some(true),
    );

    // check use case for QWORD
    let rules = vec![(
        libc::SYS_ioctl,
        vec![SeccompRule::new(vec![
            Cond::new(2, Qword, Le, u64::from(std::u32::MAX) + 10).unwrap()
        ])
        .unwrap()],
    )];
    // check syscalls that are supposed to work
    validate_seccomp_filter(
        rules.clone(),
        || unsafe {
            libc::ioctl(0, 0, u64::from(std::u32::MAX) + 10);
            libc::ioctl(0, 0, u64::from(std::u32::MAX) + 9);
        },
        Some(false),
    );
    // check syscalls that are not supposed to work
    validate_seccomp_filter(
        rules,
        || unsafe {
            libc::ioctl(0, 0, u64::from(std::u32::MAX) + 11);
        },
        Some(true),
    );
}

#[test]
fn test_lt_operator() {
    // check use case for DWORD
    let rules = vec![(
        libc::SYS_ioctl,
        vec![SeccompRule::new(vec![Cond::new(1, Dword, Lt, KVM_GET_PIT2).unwrap()]).unwrap()],
    )];
    // check syscalls that are supposed to work
    validate_seccomp_filter(
        rules.clone(),
        || unsafe {
            libc::ioctl(0, (KVM_GET_PIT2 - 1) as IoctlRequest);
        },
        Some(false),
    );
    // check syscalls that are not supposed to work
    validate_seccomp_filter(
        rules,
        || unsafe {
            libc::ioctl(0, KVM_GET_PIT2 as IoctlRequest);
        },
        Some(true),
    );

    // check use case for QWORD
    let rules = vec![(
        libc::SYS_ioctl,
        vec![SeccompRule::new(vec![
            Cond::new(2, Qword, Lt, u64::from(std::u32::MAX) + 10).unwrap()
        ])
        .unwrap()],
    )];
    // check syscalls that are supposed to work
    validate_seccomp_filter(
        rules.clone(),
        || unsafe {
            libc::ioctl(0, 0, u64::from(std::u32::MAX) + 9);
        },
        Some(false),
    );
    // check syscalls that are not supposed to work
    validate_seccomp_filter(
        rules,
        || unsafe {
            libc::ioctl(0, 0, u64::from(std::u32::MAX) + 10);
        },
        Some(true),
    );
}

#[test]
fn test_masked_eq_operator() {
    // check use case for DWORD
    let rules = vec![(
        libc::SYS_ioctl,
        vec![SeccompRule::new(vec![Cond::new(
            1,
            Dword,
            MaskedEq(KVM_GET_PIT2_MSB),
            KVM_GET_PIT2,
        )
        .unwrap()])
        .unwrap()],
    )];
    // check syscalls that are supposed to work
    validate_seccomp_filter(
        rules.clone(),
        || unsafe {
            libc::ioctl(0, KVM_GET_PIT2 as IoctlRequest);
            libc::ioctl(0, KVM_GET_PIT2_MSB as IoctlRequest);
        },
        Some(false),
    );
    // check syscalls that are not supposed to work
    validate_seccomp_filter(
        rules,
        || unsafe {
            libc::ioctl(0, KVM_GET_PIT2_LSB as IoctlRequest);
        },
        Some(true),
    );

    // check use case for QWORD
    let rules = vec![(
        libc::SYS_ioctl,
        vec![SeccompRule::new(vec![Cond::new(
            2,
            Qword,
            MaskedEq(u64::from(std::u32::MAX)),
            u64::MAX,
        )
        .unwrap()])
        .unwrap()],
    )];
    // check syscalls that are supposed to work
    validate_seccomp_filter(
        rules.clone(),
        || unsafe {
            libc::ioctl(0, 0, u64::from(std::u32::MAX));
            libc::ioctl(0, 0, u64::MAX);
        },
        Some(false),
    );
    // check syscalls that are not supposed to work
    validate_seccomp_filter(
        rules,
        || unsafe {
            libc::ioctl(0, 0, 0);
        },
        Some(true),
    );
}

#[test]
fn test_ne_operator() {
    // check use case for DWORD
    let rules = vec![(
        libc::SYS_ioctl,
        vec![SeccompRule::new(vec![Cond::new(1, Dword, Ne, KVM_GET_PIT2).unwrap()]).unwrap()],
    )];
    // check syscalls that are supposed to work
    validate_seccomp_filter(
        rules.clone(),
        || unsafe {
            libc::ioctl(0, 0);
        },
        Some(false),
    );
    // check syscalls that are not supposed to work
    validate_seccomp_filter(
        rules,
        || unsafe {
            libc::ioctl(0, KVM_GET_PIT2 as IoctlRequest);
        },
        Some(true),
    );

    // check use case for QWORD
    let rules = vec![(
        libc::SYS_ioctl,
        vec![SeccompRule::new(vec![Cond::new(2, Qword, Ne, u64::MAX).unwrap()]).unwrap()],
    )];
    // check syscalls that are supposed to work
    validate_seccomp_filter(
        rules.clone(),
        || unsafe {
            libc::ioctl(0, 0, 0);
        },
        Some(false),
    );
    // check syscalls that are not supposed to work
    validate_seccomp_filter(
        rules,
        || unsafe {
            libc::ioctl(0, 0, u64::MAX);
        },
        Some(true),
    );
}

#[test]
fn test_complex_filter() {
    let rules = vec![
        (
            libc::SYS_ioctl,
            vec![
                SeccompRule::new(vec![
                    Cond::new(2, Dword, Le, 14).unwrap(),
                    Cond::new(2, Dword, Ne, 13).unwrap(),
                ])
                .unwrap(),
                SeccompRule::new(vec![
                    Cond::new(2, Dword, Gt, 20).unwrap(),
                    Cond::new(2, Dword, Lt, 40).unwrap(),
                ])
                .unwrap(),
                SeccompRule::new(vec![
                    Cond::new(0, Dword, Eq, 1).unwrap(),
                    Cond::new(2, Dword, Eq, 15).unwrap(),
                ])
                .unwrap(),
                SeccompRule::new(vec![
                    Cond::new(2, Qword, Eq, std::u32::MAX as u64 + 41).unwrap()
                ])
                .unwrap(),
            ],
        ),
        (
            libc::SYS_madvise,
            vec![SeccompRule::new(vec![
                Cond::new(0, Dword, Eq, 0).unwrap(),
                Cond::new(1, Dword, Eq, 0).unwrap(),
            ])
            .unwrap()],
        ),
        (libc::SYS_getpid, vec![]),
    ];
    // check syscalls that are supposed to work
    {
        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                libc::ioctl(0, 0, 12);
            },
            Some(false),
        );

        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                libc::ioctl(0, 0, 14);
            },
            Some(false),
        );

        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                libc::ioctl(0, 0, 21);
            },
            Some(false),
        );

        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                libc::ioctl(0, 0, 39);
            },
            Some(false),
        );

        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                libc::ioctl(1, 0, 15);
            },
            Some(false),
        );

        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                libc::ioctl(0, 0, std::u32::MAX as u64 + 41);
            },
            Some(false),
        );

        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                libc::madvise(std::ptr::null_mut(), 0, 0);
            },
            Some(false),
        );

        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                assert!(libc::getpid() > 0);
            },
            None,
        );
    }

    // check syscalls that are not supposed to work
    {
        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                libc::ioctl(0, 0, 13);
            },
            Some(true),
        );

        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                libc::ioctl(0, 0, 16);
            },
            Some(true),
        );

        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                libc::ioctl(0, 0, 17);
            },
            Some(true),
        );

        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                libc::ioctl(0, 0, 18);
            },
            Some(true),
        );

        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                libc::ioctl(0, 0, 19);
            },
            Some(true),
        );

        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                libc::ioctl(0, 0, 20);
            },
            Some(true),
        );

        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                libc::ioctl(0, 0, std::u32::MAX as u64 + 42);
            },
            Some(true),
        );

        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                libc::madvise(std::ptr::null_mut(), 1, 0);
            },
            Some(true),
        );

        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                assert_eq!(libc::getuid() as i32, -FAILURE_CODE);
            },
            None,
        );
    }
}
