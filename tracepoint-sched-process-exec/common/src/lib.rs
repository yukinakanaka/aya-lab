#![no_std]

pub const MAX_PATH: usize = 512;
pub const MAX_ARG_LENGTH: usize = 1024;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ProcessExecEvent {
    pub uid: u32,
    pub pid: i32,
    pub filename: [u8; MAX_PATH],
    pub filename_len: usize,
    pub args: [u8; MAX_ARG_LENGTH],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessExecEvent {}
