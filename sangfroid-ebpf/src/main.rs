#![no_std]
#![no_main]

use aya_bpf::{macros::btf_tracepoint, programs::BtfTracePointContext};
use aya_log_ebpf::info;
mod vmlinux;

use vmlinux::{task_struct};

#[btf_tracepoint(name = "sched_process_fork")]
pub fn sangfroid(ctx: BtfTracePointContext) -> u32 {
    match try_sched_process_fork(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sched_process_fork(ctx: BtfTracePointContext) -> Result<u32, u32> {
    let parent_task: *const task_struct = unsafe { ctx.arg(0) };
    let task: *const task_struct = unsafe { ctx.arg(1) };

    let ppid = unsafe { (*parent_task).pid };
    let pid = unsafe { (*task).pid };

    let namespaces = get_task_namespaces(task);
    let process = Process {
        id: pid,
        parent_id: ppid,
        namespaces,
    };

    info!(&ctx, "tracepoint sched_process_exe called: id={} ppid={} mnt_id={}, uts_id={}, ipc_id={}, cgroup_id={}, pid_id={}, pid_for_children_id={}", process.id, process.parent_id, process.namespaces.mnt_id, process.namespaces.uts_id, process.namespaces.ipc_id, process.namespaces.cgroup_id, process.namespaces.pid_id, process.namespaces.pid_for_children_id);
    Ok(0)
}

fn get_task_namespaces(task: *const task_struct) -> ProcessNamespaces {
    let nsproxy = unsafe { &*(*task).nsproxy };

    let thread_pid = unsafe { (*task).thread_pid };
    let pid_id = if !thread_pid.is_null() {
        let level = unsafe { (*thread_pid).level };
        let up = unsafe { (*thread_pid).numbers[level as usize] };
        unsafe { (*up.ns).ns.inum }
    } else {
        0
    };

    ProcessNamespaces {
        mnt_id: unsafe { (*nsproxy.mnt_ns).ns.inum },
        uts_id: unsafe { (*nsproxy.uts_ns).ns.inum },
        ipc_id: unsafe { (*nsproxy.ipc_ns).ns.inum },
        cgroup_id: unsafe { (*nsproxy.cgroup_ns).ns.inum },
        pid_id,
        pid_for_children_id: unsafe { (*nsproxy.pid_ns_for_children).ns.inum },
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[derive(Debug)]
struct ProcessNamespaces {
    mnt_id: u32,
    uts_id: u32,
    ipc_id: u32,
    cgroup_id: u32,
    pid_id: u32,
    pid_for_children_id: u32,
}

#[derive(Debug)]
struct Process {
    id: i32,
    parent_id: i32,
    namespaces: ProcessNamespaces,
}
