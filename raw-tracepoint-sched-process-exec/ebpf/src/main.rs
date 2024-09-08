#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings;
use bindings::{linux_binprm, pid_t, task_struct};

use aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes;
use aya_ebpf::{macros::btf_tracepoint, programs::BtfTracePointContext, EbpfContext};

use aya_log_ebpf::info;

#[btf_tracepoint(function = "sched_process_exec")]
pub fn raw_trace_sched_process_exec(ctx: BtfTracePointContext) -> u32 {
    match unsafe { try_raw_trace_sched_process_exec(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap(),
    }
}

unsafe fn try_raw_trace_sched_process_exec(ctx: BtfTracePointContext) -> Result<u32, i64> {
    /*
    Kernal Code: https://github.com/torvalds/linux/blob/5189dafa4cf950e675f02ee04b577dfbbad0d9b1/include/trace/events/sched.h#L397C1-L421C3

    Tracepoint for exec:

    TRACE_EVENT(sched_process_exec,
        TP_PROTO(struct task_struct *p, pid_t old_pid,
             struct linux_binprm *bprm),
        TP_ARGS(p, old_pid, bprm),
        TP_STRUCT__entry(
            __string(	filename,	bprm->filename	)
            __field(	pid_t,		pid		)
            __field(	pid_t,		old_pid		)
        ),
        TP_fast_assign(
            __assign_str(filename);
            __entry->pid		= p->pid;
            __entry->old_pid	= old_pid;
        ),
        TP_printk("filename=%s pid=%d old_pid=%d", __get_str(filename),
              __entry->pid, __entry->old_pid)
    );
    */

    // Get arguments as raw pointers
    let task: *const task_struct = ctx.arg(0);
    let old_pid: pid_t = ctx.arg(1);
    let linux_binprm: *const linux_binprm = ctx.arg(2);

    // Create safe references to them
    let task = &*task;
    let linux_binprm: &linux_binprm = &*linux_binprm;

    // Use some values of the references
    // Get filename as str using the linux_binprm reference
    let mut buf = [0u8; 32];
    let filename_ptr = linux_binprm.filename;
    let filename = bpf_probe_read_kernel_str_bytes(filename_ptr, &mut buf)
        .map(|s| core::str::from_utf8_unchecked(s))?;

    // Check if getting arguments and ctx are working fine
    info!(
        &ctx,
        "task.pid: {}, old_pid: {}, linux_binprm.filename: {}, ctx.uid: {}",
        task.pid,
        old_pid,
        filename,
        ctx.uid()
    );

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
