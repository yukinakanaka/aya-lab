use aya::{
    include_bytes_aligned, maps::perf::AsyncPerfEventArray, programs::TracePoint,
    util::online_cpus, Bpf,
};

use aya_log::BpfLogger;
use bytes::BytesMut;

use common::ProcessExecEvent;
use std::convert::{TryFrom, TryInto};
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
        "../../target/bpfel-unknown-none/debug/trace_sched_process_exec"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/trace_sched_process_exec"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut TracePoint = bpf
        .program_mut("trace_sched_process_exec")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;

    // Process events from the perf buffer
    let cpus = online_cpus()?;
    let num_cpus = cpus.len();
    let mut events = AsyncPerfEventArray::try_from(bpf.take_map("events").unwrap())?;
    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;

        tokio::task::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(10240))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    // read the event
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const ProcessExecEvent;
                    let data = unsafe { ptr.read_unaligned() };

                    // parse out the data
                    let filename = String::from_utf8(data.filename[..data.filename_len].to_vec())
                        .unwrap_or("Unknown".to_owned());

                    // parse arg
                    info!("args: {}", data.args[0]);
                    let args = String::from_utf8(
                        data.args
                            .split(|&b| b == 0) // Split by null (`\0`) bytes
                            .filter(|s| !s.is_empty()) // Remove empty slices
                            .collect::<Vec<_>>() // Convert to `Vec<Vec<u8>>`
                            .join(&b' '), // Join elements with a space (`b' '`)
                    )
                    .unwrap_or("Unknown".to_owned());

                    info!(
                        "{} {} {} {} {}",
                        data.pid, data.uid, filename, data.filename_len, args
                    );
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
