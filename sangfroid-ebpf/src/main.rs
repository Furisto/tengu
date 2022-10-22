#![no_std]
#![no_main]

use aya_bpf::{
    macros::btf_tracepoint,
    programs::{BtfTracePointContext}, bindings::task_struct,
};
use aya_log_ebpf::info;

#[btf_tracepoint(name="sched_process_fork")]
pub fn sangfroid(ctx: BtfTracePointContext) -> u32 {
    match try_sched_process_fork(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sched_process_fork(ctx: BtfTracePointContext) -> Result<u32, u32> {
    let parent_task: *const task_struct = unsafe { ctx.arg(0) };
    let child_task: *const task_struct = unsafe { ctx.arg(1) };

    info!(&ctx, "tracepoint sched_process_exe called: {}", pid);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
