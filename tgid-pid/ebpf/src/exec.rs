use aya_ebpf::helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid};
use aya_ebpf::{macros::btf_tracepoint, programs::BtfTracePointContext};

use aya_log_ebpf::info;

#[btf_tracepoint(function = "event_execve")]
pub fn event_execve(ctx: BtfTracePointContext) -> u32 {
    match unsafe { try_event_execve(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap(),
    }
}

unsafe fn try_event_execve(ctx: BtfTracePointContext) -> Result<u32, i64> {
    // https://github.com/torvalds/linux/blob/aa22f4da2a46b484a257d167c67a2adc1b7aaf68/include/trace/events/sched.h#L397-L421
    /*
     * Tracepoint for exec:
     */
    // TRACE_EVENT(sched_process_exec,

    // 	TP_PROTO(struct task_struct *p, pid_t old_pid,
    // 		 struct linux_binprm *bprm),

    // 	TP_ARGS(p, old_pid, bprm),

    // 	TP_STRUCT__entry(
    // 		__string(	filename,	bprm->filename	)
    // 		__field(	pid_t,		pid		)
    // 		__field(	pid_t,		old_pid		)
    // 	),

    // 	TP_fast_assign(
    // 		__assign_str(filename);
    // 		__entry->pid		= p->pid;
    // 		__entry->old_pid	= old_pid;
    // 	),

    // 	TP_printk("filename=%s pid=%d old_pid=%d", __get_str(filename),
    // 		  __entry->pid, __entry->old_pid)
    // );

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
