#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings;
use bindings::trace_event_raw_sched_process_exec;
use bindings::{mm_struct, task_struct};

use aya_ebpf::helpers::{bpf_get_current_task, bpf_probe_read_kernel};
use aya_ebpf::helpers::{bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_str_bytes};
use aya_ebpf_bindings::helpers::bpf_probe_read_user;
use aya_ebpf_cty::c_void;

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::{PerCpuArray, PerfEventArray},
    programs::TracePointContext,
    EbpfContext,
};

use aya_log_ebpf::info;
use common::{ProcessExecEvent, MAX_ARG_LENGTH};

#[map(name = "data_heap")]
pub static mut DATA_HEAP: PerCpuArray<ProcessExecEvent> = PerCpuArray::with_max_entries(1, 0);

#[repr(C)]
pub struct Buf {
    pub buf: [u8; 256],
}
#[map(name = "garbage")]
pub static mut GARBAGE: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);

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
    if ctx.uid() != 1000 {
        return Ok(0);
    }
    let trace_event: trace_event_raw_sched_process_exec =
        ctx.read_at::<trace_event_raw_sched_process_exec>(0)?;

    // get the map-backed buffer that we're going to use as storage for the process_event
    let event = unsafe {
        let ptr = DATA_HEAP.get_ptr_mut(0).ok_or(0)?;
        &mut *ptr
    };
    event.uid = ctx.uid();
    event.pid = trace_event.pid;

    // __data_loc_filename
    // Lower 16bit is the offset against the beginning of the event entry.
    let offset = (trace_event.__data_loc_filename & 0xFFFF) as usize;
    // read filename from a dynamic array in kernel and store it in buffer
    let data = bpf_probe_read_kernel_str_bytes(
        ctx.as_ptr().add(offset) as *const u8,
        &mut event.filename,
    )?;

    // Higher 16bit is the length of the array
    let len = (trace_event.__data_loc_filename >> 16 & 0xFFFF) as usize - 1;
    event.filename_len = len;

    info!(
        &ctx,
        "{} {} {} {}",
        event.pid,
        ctx.uid(),
        core::str::from_utf8_unchecked(data),
        len,
    );

    let task = bpf_get_current_task() as *const task_struct;
    // let exit_code = bpf_probe_read_kernel(&(*task).exit_code).unwrap_or(1);
    let mm: *mut mm_struct = bpf_probe_read_kernel(&(*task).mm)?;
    let arg_start = bpf_probe_read_kernel(&(*mm).__bindgen_anon_1.arg_start)?;
    let arg_end = bpf_probe_read_kernel(&(*mm).__bindgen_anon_1.arg_end)?;

    // let arg_size = end_stack - start_stack;
    let arg_size = arg_end - arg_start;
    info!(&ctx, "{} {} {}", arg_start, arg_end, arg_size);

    // First argument is binary path
    let garbage = unsafe {
        let ptr = GARBAGE.get_ptr_mut(0).ok_or(0)?;
        &mut *ptr
    };
    let binary_path = bpf_probe_read_user_str_bytes(arg_start as *const u8, &mut garbage.buf)?;
    info!(
        &ctx,
        "binary_path: {} length: {}",
        core::str::from_utf8_unchecked(binary_path),
        binary_path.len()
    );
    let arg_start = arg_start + binary_path.len() as u64 + 1;

    let args_len = (arg_end - arg_start) as u32;
    let args_len = args_len.min(MAX_ARG_LENGTH as u32); // to pass verifier check
    info!(&ctx, "args_len: {}", args_len);
    bpf_probe_read_user(
        event.args.as_mut_ptr() as *mut c_void,
        args_len,
        arg_start as *const c_void,
    );

    EVENTS.output(&ctx, &event, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
