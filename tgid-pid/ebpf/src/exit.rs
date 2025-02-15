use aya_ebpf::helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid};
use aya_ebpf::{macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::*;

#[kprobe(function = "acct_process")]
pub fn acct_process(ctx: ProbeContext) -> u32 {
    match unsafe { try_acct_process(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap(),
    }
}

unsafe fn try_acct_process(ctx: ProbeContext) -> Result<u32, i64> {
    let uid: u32 = bpf_get_current_uid_gid() as u32;

    let tgid: u32 = (bpf_get_current_pid_tgid() >> 32).try_into().unwrap();
    let pid: u32 = bpf_get_current_pid_tgid() as u32;

    let comm = bpf_get_current_comm().unwrap();

    info!(
        &ctx,
        "comm: {}\ttgid: {}\tpid: {}\tuid: {}",
        core::str::from_utf8_unchecked(&comm),
        tgid,
        pid,
        uid
    );
    Ok(0)
}
