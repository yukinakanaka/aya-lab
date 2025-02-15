use aya::programs::{BtfTracePoint, KProbe};
use aya::{include_bytes_aligned, Bpf, Btf};
use aya_log::BpfLogger;

use std::convert::TryInto;
use tokio::signal;
use tracing::{debug, info, warn};
use tracing_subscriber::filter::{EnvFilter, LevelFilter};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .without_time()
        .init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the new memcg
    // based accounting
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };

    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at runtime.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/ebpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/ebpf"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let btf = Btf::from_sys_fs()?;

    let program: &mut KProbe = bpf.program_mut("wake_up_new_task").unwrap().try_into()?;
    program.load()?;
    program.attach("wake_up_new_task", 0)?;

    let program: &mut BtfTracePoint = bpf.program_mut("event_execve").unwrap().try_into()?;
    program.load("sched_process_exec", &btf)?;
    program.attach()?;

    let program: &mut KProbe = bpf.program_mut("acct_process").unwrap().try_into()?;
    program.load()?;
    // program.attach("acct_process", 0)?;
    program.attach("do_exit", 0)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
