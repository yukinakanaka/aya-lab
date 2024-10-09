use aya::{
    include_bytes_aligned,
    maps::{MapData, ProgramArray},
    programs::BtfTracePoint,
    Bpf, Btf,
};

use aya_log::BpfLogger;
use tracing::*;

pub const TAIL_CALL_MAP: &str = "TAIL_CALL_MAP";
pub const ATTACHED_FUNCTION: &str = "prog1";
pub const TAIL_CALLED_FUNCTIONS: [&str; 2] = ["prog2", "prog3"];
pub const TRACE_POINT: &str = "sched_process_exec";

/// The `BpfExecutionContext` struct holds references
/// that prevent the BPF programs and maps from being unloaded
pub struct BpfExecutionContext {
    #[allow(dead_code)]
    bpf: Bpf,
    #[allow(dead_code)]
    tail_call_map: ProgramArray<MapData>,
}

pub fn configure_bpf() -> anyhow::Result<BpfExecutionContext> {
    set_memory_limit()?;

    let mut bpf = load_bpf_program()?;
    initialize_bpf_logger(&mut bpf)?;

    let btf = Btf::from_sys_fs()?;
    let mut tail_call_map = ProgramArray::try_from(bpf.take_map(TAIL_CALL_MAP).unwrap())?;

    load_programs(&mut bpf, &btf, &mut tail_call_map)?;

    Ok(BpfExecutionContext { bpf, tail_call_map })
}

fn set_memory_limit() -> anyhow::Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };

    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("Failed to remove limit on locked memory, ret is: {}", ret);
    }
    Ok(())
}

fn load_bpf_program() -> anyhow::Result<Bpf> {
    #[cfg(debug_assertions)]
    let bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/ebpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/ebpf"
    ))?;
    Ok(bpf)
}

fn initialize_bpf_logger(bpf: &mut Bpf) -> anyhow::Result<()> {
    if let Err(e) = BpfLogger::init(bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("Failed to initialize eBPF logger: {}", e);
    }
    Ok(())
}

fn load_programs(
    bpf: &mut Bpf,
    btf: &Btf,
    tail_call_map: &mut ProgramArray<MapData>,
) -> anyhow::Result<()> {
    let flags = 0;

    for (index, function) in TAIL_CALLED_FUNCTIONS.iter().enumerate() {
        load_tail_called_program(bpf, btf, tail_call_map, function, index as u32, flags)?;
    }

    let attached_program: &mut BtfTracePoint =
        bpf.program_mut(ATTACHED_FUNCTION).unwrap().try_into()?;
    attached_program.load(TRACE_POINT, btf)?;
    attached_program.attach()?;

    Ok(())
}

fn load_tail_called_program(
    bpf: &mut Bpf,
    btf: &Btf,
    tail_call_map: &mut ProgramArray<MapData>,
    function_name: &str,
    index: u32,
    flags: u64,
) -> anyhow::Result<()> {
    let program: &mut BtfTracePoint = bpf.program_mut(function_name).unwrap().try_into()?;
    program.load(TRACE_POINT, btf)?;
    let fd = program.fd().unwrap();
    tail_call_map.set(index, fd, flags)?;
    debug!("set {} in tail_call_map", function_name);

    Ok(())
}
