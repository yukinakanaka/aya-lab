#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings;
use bindings::trace_event_raw_sched_process_exec;

use aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes;
use aya_ebpf::{
    macros::{map, tracepoint},
    maps::{PerCpuArray, PerfEventArray},
    programs::TracePointContext,
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

#[tracepoint(category = "sched", name = "sched_process_exec")]
pub fn trace_sched_process_exec(ctx: TracePointContext) -> u32 {
    match unsafe { try_trace_sched_process_exec(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap(),
    }
}

unsafe fn try_trace_sched_process_exec(ctx: TracePointContext) -> Result<u32, i64> {
    let event: trace_event_raw_sched_process_exec =
        ctx.read_at::<trace_event_raw_sched_process_exec>(0)?;

    // get the map-backed buffer that we're going to use as storage for the process_event
    let buf = unsafe {
        let ptr = DATA_HEAP.get_ptr_mut(0).ok_or(0)?;
        &mut *ptr
    };
    buf.p.uid = ctx.uid();
    buf.p.pid = event.pid;

    // __data_loc_filename
    // Lower 16bit is the offset against the beginning of the event entry.
    let offset = (event.__data_loc_filename & 0xFFFF) as usize;
    // read filename from a dynamic array in kernel and store it in buffer
    let data = bpf_probe_read_kernel_str_bytes(
        ctx.as_ptr().add(offset) as *const u8,
        &mut buf.p.filename,
    )?;

    // Higher 16bit is the length of the array
    let len = (event.__data_loc_filename >> 16 & 0xFFFF) as usize - 1;
    buf.p.filename_len = len;

    info!(
        &ctx,
        "{} {} {} {}",
        event.pid,
        ctx.uid(),
        core::str::from_utf8_unchecked(data),
        len,
    );

    EVENTS.output(&ctx, &buf.p, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
