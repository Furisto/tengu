use aya::maps::perf::AsyncPerfEventArray;
use aya::maps::{HashMap as BpfHashMap, MapRefMut};
use aya::programs::BtfTracePoint;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf, Btf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::{info, warn};
use tengu_common::{BtfEvent, BtfEventKind, CgroupData, Process};
use tokio::{signal, sync::mpsc, task};

#[derive(Debug, Parser)]
struct Opt {}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    let btf = Btf::from_sys_fs()?;

    env_logger::init();

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/tengu"
    ))?;

    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/tengu"
    ))?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let procs_program: &mut BtfTracePoint =
        bpf.program_mut("sched_process_fork").unwrap().try_into()?;
    procs_program.load("sched_process_fork", &btf)?;
    procs_program.attach()?;

    let cgroup_mkdir: &mut BtfTracePoint = bpf.program_mut("cgroup_mkdir").unwrap().try_into()?;
    cgroup_mkdir.load("cgroup_mkdir", &btf)?;
    cgroup_mkdir.attach()?;

    let cgroup_rmdir: &mut BtfTracePoint = bpf.program_mut("cgroup_rmdir").unwrap().try_into()?;
    cgroup_rmdir.load("cgroup_rmdir", &btf)?;
    cgroup_rmdir.attach()?;

    let cgroup_attach: &mut BtfTracePoint =
        bpf.program_mut("cgroup_attach_task").unwrap().try_into()?;
    cgroup_attach.load("cgroup_attach_task", &btf)?;
    cgroup_attach.attach()?;

    let cgroups: BpfHashMap<MapRefMut, u64, CgroupData> =
        BpfHashMap::try_from(bpf.map_mut("CGROUPS")?)?;
    let processes: BpfHashMap<MapRefMut, u64, Process> =
        BpfHashMap::try_from(bpf.map_mut("PROCESSES")?)?;
    let mut events = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;

    let (tx, mut rx) = mpsc::channel::<BtfEvent>(100);
    task::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event.kind {
                BtfEventKind::Cgroup => {
                    let cgroup_data = cgroups.get(&event.key, 0).unwrap();
                    println!("Cgroup {} created", cgroup_data.id);
                }
                BtfEventKind::Process => {
                    let process = processes.get(&event.key, 0);
                    println!("{:?}", process)
                }
            }
        }
    });

    for cpu_id in online_cpus()? {
        let mut event_array = events.open(cpu_id, None)?;
        let tx = tx.clone();

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = event_array.read_events(&mut buffers).await.unwrap();
                let mut results = vec![];
                for b in buffers.iter_mut().take(events.read) {
                    let event_ptr = b.as_ptr() as *const BtfEvent;
                    let event_data = unsafe { event_ptr.read_unaligned() };
                    results.push(event_data);
                }

                for event in results {
                    tx.send(event).await.unwrap();
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
