#![no_std]
#![no_main]

mod bindings;
use bindings::{linux_binprm, pid_t, task_struct};

use aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes;
use aya_ebpf::{
    macros::{btf_tracepoint, map},
    maps::{PerCpuArray, PerfEventArray},
    programs::BtfTracePointContext,
    EbpfContext,
};

use aya_log_ebpf::info;
use common::ProcessExecEvent;

#[repr(C)]
pub struct ProcessExecEventBuf {
    pub p: ProcessExecEvent,
}

#[map(name = "data_heap")]
pub static mut DATA_HEAP: PerCpuArray<ProcessExecEventBuf> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "events")]
pub static EVENTS: PerfEventArray<ProcessExecEvent> = PerfEventArray::new(0);

#[btf_tracepoint(function = "sched_process_exec")]
pub fn trace_sched_process_exec(ctx: BtfTracePointContext) -> i32 {
    match unsafe { try_trace_sched_process_exec(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap(),
    }
}

unsafe fn try_trace_sched_process_exec(ctx: BtfTracePointContext) -> Result<i32, i64> {
    // get the map-backed buffer that we're going to use as storage for the process_event
    let buf = unsafe {
        let ptr = DATA_HEAP.get_ptr_mut(0).ok_or(0)?;
        &mut *ptr
    };

    // https://github.com/torvalds/linux/blob/43db1e03c086ed20cc75808d3f45e780ec4ca26e/include/trace/events/sched.h#L400-L421
    let task: *const task_struct = ctx.arg(0);
    let old_pid: pid_t = ctx.arg(1);
    let linux_binprm: *const linux_binprm = ctx.arg(2);

    let ppid = (*(*task).parent).pid;
    let pid = (*task).pid;

    buf.p.uid = ctx.uid();
    buf.p.pid = pid;

    let filename_ptr = (*linux_binprm).filename;
    let filename = bpf_probe_read_kernel_str_bytes(filename_ptr, &mut buf.p.filename)
        .map(|s| core::str::from_utf8_unchecked(s))?;

    buf.p.filename_len = filename.len();

    info!(
        &ctx,
        "ppid:{}, pid: {}, uid: {}, old_pid: {}, filename: {}",
        ppid,
        pid,
        old_pid,
        ctx.uid(),
        filename
    );

    EVENTS.output(&ctx, &buf.p, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
