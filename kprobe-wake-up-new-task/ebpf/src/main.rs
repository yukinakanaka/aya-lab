#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings;
use bindings::{pid_t, task_struct};

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read},
    macros::kprobe,
    programs::ProbeContext,
};
use aya_log_ebpf::*;

#[kprobe(function = "wake_up_new_task")]
pub fn wake_up_new_task(ctx: ProbeContext) -> u32 {
    // https://github.com/torvalds/linux/blob/d1f2d51b711a3b7f1ae1b46701c769c1d580fa7f/kernel/sched/core.c#L4659-L4665
    // /*
    //  * wake_up_new_task - wake up a newly created task for the first time.
    //  *
    //  * This function will do some initial scheduler statistics housekeeping
    //  * that must be done for every newly created context, then puts the task
    //  * on the runqueue and wakes it.
    //  */
    //
    // Arguments:
    // void wake_up_new_task(struct task_struct *p)

    match unsafe { try_wake_up_new_task(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap(),
    }
}

unsafe fn try_wake_up_new_task(ctx: ProbeContext) -> Result<u32, i64> {
    let caller_tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    trace!(&ctx, "Start wake_up_new_task. caller: {}", caller_tgid);

    // Get arguments as raw pointers
    let task: *const task_struct = ctx.arg(0).ok_or(1)?;

    // Read values from task_struct
    let comm = bpf_probe_read(&(*task).comm as *const [::aya_ebpf::cty::c_char; 16usize])?;
    let comm = core::str::from_utf8_unchecked(&comm);
    let tgid = bpf_probe_read(&(*task).tgid as *const pid_t)?;
    let tid = bpf_probe_read(&(*task).pid as *const pid_t)?;

    info!(
        &ctx,
        "wake_up_new_task. comm: {}, tgid: {}, tid: {}, caller: {}.", comm, tgid, tid, caller_tgid
    );
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
