use aya_tool::generate::InputFile;
use std::{fs::File, io::Write, path::PathBuf};

pub fn generate() -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("ebpf/src");
    let names = vec!["trace_event_raw_sched_process_exec", "task_struct"];
    let vmlinux = aya_tool::generate(
        InputFile::Btf(PathBuf::from("/sys/kernel/btf/vmlinux")),
        &names,
        &[],
    )?;
    let mut out = File::create(dir.join("vmlinux.rs"))?;
    write!(out, "{}", vmlinux)?;
    Ok(())
}
