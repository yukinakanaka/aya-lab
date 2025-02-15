use crate::vmlinux::{pid_t, task_struct};
use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_kernel,
    },
    macros::kprobe,
    programs::ProbeContext,
};
use aya_log_ebpf::*;

#[kprobe(function = "wake_up_new_task")]
pub fn wake_up_new_task(ctx: ProbeContext) -> u32 {
    match unsafe { try_wake_up_new_task(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap(),
    }
}

unsafe fn try_wake_up_new_task(ctx: ProbeContext) -> Result<u32, i64> {
    let current_uid: u32 = bpf_get_current_uid_gid() as u32;

    let current_tgid: u32 = (bpf_get_current_pid_tgid() >> 32).try_into().unwrap();
    let current_pid: u32 = bpf_get_current_pid_tgid() as u32;
    let current_comm = bpf_get_current_comm().unwrap();

    let task: *const task_struct = ctx.arg(0).ok_or(1)?;
    let task_tgid = bpf_probe_read_kernel(&(*task).tgid as *const pid_t)?.unsigned_abs();
    let task_tid = bpf_probe_read_kernel(&(*task).pid as *const pid_t)?.unsigned_abs();
    let task_comm = bpf_probe_read_kernel(&(*task).comm as *const [u8; 16])?;

    info!(
        &ctx,
        "comm: {}\ttgid: {}\tpid: {}\tuid: {}\tt_comm: {}\tt_tgid: {}\tt_tid: {}",
        core::str::from_utf8_unchecked(&current_comm),
        current_tgid,
        current_pid,
        current_uid,
        core::str::from_utf8_unchecked(&task_comm),
        task_tgid,
        task_tid,
    );

    Ok(0)
}
