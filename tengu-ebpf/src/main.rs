#![no_std]
#![no_main]

use core::slice;

use aya_bpf::{
    macros::{btf_tracepoint, map, raw_tracepoint},
    maps::{HashMap,PerfEventArray},
    programs::{BtfTracePointContext, RawTracePointContext},
    BpfContext, helpers::{bpf_probe_read_kernel, bpf_get_current_pid_tgid},
};
use aya_log_ebpf::info;
mod vmlinux;

use tengu_common::{CgroupData, BtfEvent, ProcessNamespaces, Process, BtfEventKind};
use vmlinux::{cgroup, task_struct};

#[map]
pub static mut CGROUPS: HashMap<u64, CgroupData> = HashMap::with_max_entries(16384, 0);

#[map]
pub static mut EVENTS:PerfEventArray<BtfEvent> = PerfEventArray::with_max_entries(1024, 0);

#[map]
pub static mut PROCESSES: HashMap<u64, Process> = HashMap::with_max_entries(16384, 0);

#[btf_tracepoint(name = "sched_process_fork")]
pub fn sched_process_fork(ctx: BtfTracePointContext) -> u32 {
    unsafe {
        match try_sched_process_fork(ctx) {
            Ok(ret) => ret,
            Err(ret) => ret,
        }
    }
}

#[btf_tracepoint(name = "cgroup_mkdir")]
pub fn cgroup_mkdir(ctx: BtfTracePointContext) -> u32 {
    unsafe {
        match try_cgroup_mkdir(ctx) {
            Ok(ret) => ret,
            Err(ret) => ret,
        }
    }
}

#[btf_tracepoint(name = "cgroup_rmdir")]
pub fn cgroup_rmdir(ctx: BtfTracePointContext) -> u32 {
    unsafe {
        match try_cgroup_rmdir(ctx) {
            Ok(ret) => ret,
            Err(ret) => ret,
        }
    }
}

#[btf_tracepoint(name = "cgroup_attach_task")]
pub fn cgroup_attach_task(ctx: BtfTracePointContext) -> u32 {
    unsafe {
        match try_cgroup_attach_task(ctx) {
            Ok(ret) => ret,
            Err(ret) => ret,
        }
    }
}

#[raw_tracepoint(name = "sys_enter")]
pub fn sys_enter(ctx: RawTracePointContext) -> u32 {
    unsafe {
        match try_sys_enter(ctx) {
            Ok(ret) => ret,
            Err(ret) => ret,
        }
    }
}

unsafe fn try_sched_process_fork(ctx: BtfTracePointContext) -> Result<u32, u32> {
    info!(
        &ctx,
        "tracepoint sched_process_exe called");

    let parent_task: *const task_struct = ctx.arg(0);
    let task: *const task_struct = ctx.arg(1);

    let ppid = (*parent_task).pid;
    let pid = (*task).pid;

    let namespaces = get_namespaces(task);
    let process = Process {
        id: pid,
        parent_id: ppid,
        namespaces,
    };

    let pid = u64::try_from(pid).map_err(|_| 5 as u32)?;
    PROCESSES.insert(&pid, &process, 0).map_err(|e| e as u32)?;
    EVENTS.output(&ctx, &BtfEvent { key: pid, kind: BtfEventKind::Process }, 0);

    Ok(0)
}

fn get_namespaces(task: *const task_struct) -> ProcessNamespaces {
    let nsproxy = unsafe { &*(*task).nsproxy };

    ProcessNamespaces {
        mnt_id: unsafe { (*nsproxy.mnt_ns).ns.inum },
        uts_id: unsafe { (*nsproxy.uts_ns).ns.inum },
        ipc_id: unsafe { (*nsproxy.ipc_ns).ns.inum },
        cgroup_id: unsafe { (*nsproxy.cgroup_ns).ns.inum },
        pid_id: 0,
        pid_for_children_id: unsafe { (*nsproxy.pid_ns_for_children).ns.inum },
    }
}

unsafe fn try_cgroup_mkdir(ctx: BtfTracePointContext) -> Result<u32, u32> {
    info!(&ctx, "tracepoint cgroup mkdir called");

    let cgrp: *const cgroup = ctx.arg(0);
    let cgrp_id = (*(*cgrp).kn).id;

    CGROUPS.insert(&cgrp_id, &CgroupData { id: cgrp_id }, 0).map_err(|e| e as u32)?;
    EVENTS.output(&ctx, &BtfEvent { key: cgrp_id, kind: BtfEventKind::Cgroup }, 0);
   
    Ok(0)
}

unsafe fn try_cgroup_rmdir(ctx: BtfTracePointContext) -> Result<u32, u32> {
    let cgrp: *const cgroup = ctx.arg(0);
    let cgrp_id = (*(*cgrp).kn).id;

    CGROUPS.remove(&cgrp_id).map_err(|e| e as u32)?;

    info!(&ctx, "tracepoint cgroup rmdir called with id {}", cgrp_id);
    Ok(0)
}

unsafe fn try_cgroup_attach_task(ctx: BtfTracePointContext) -> Result<u32, u32> {
    let cgrp: *const cgroup = ctx.arg(0);
    let cgrp_id = (*(*cgrp).kn).id;

    let attached_task: *const task_struct = ctx.arg(2);
    let attached_pid = (*attached_task).pid;

    let attacher_pid = bpf_get_current_pid_tgid() >> 32;

    info!(&ctx, "tracepoint cgroup attach task called with for cgroup {}, attached pid: {}, attacher: {}", cgrp_id, attached_pid, attacher_pid);
    Ok(0)
}


unsafe fn try_sys_enter(ctx: RawTracePointContext) -> Result<u32, u32> {
    let args = slice::from_raw_parts(ctx.as_ptr() as *const usize, 2);
    let syscall = args[1] as u64;
    let pid = ctx.pid();

    info!(&ctx, "syscall id is {}, pid is {}", syscall, pid);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}