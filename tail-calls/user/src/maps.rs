use crate::shared_state::SharedState;
use aya_ebpf::{
    macros::map,
    maps::{PerCpuArray, ProgramArray},
};

#[map(name = "TAIL_CALL_MAP")]
pub static TAIL_CALL_MAP: ProgramArray = ProgramArray::with_max_entries(3, 0);

#[map(name = "PER_CPU_MAP")]
pub static mut PER_CPU_MAP: PerCpuArray<SharedState> = PerCpuArray::with_max_entries(1, 0);
