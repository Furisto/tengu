#![no_std]

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CgroupData {
    pub id: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for CgroupData {}

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(Debug))]
pub struct BtfEvent {
    pub key: u64,
    pub kind: BtfEventKind,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BtfEvent {}

#[repr(u64)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(Debug))]
pub enum BtfEventKind {
    Cgroup,
    Process,
}

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(Debug))]
pub struct CgroupAttach {
    id: u64,
    attached_pid: i32,
    attacher_pid: u64,
    hierarchy_id: i32,
}

pub struct ProcessEvent {
    pub id: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
pub struct Process {
    pub id: i32,
    pub parent_id: i32,
    pub namespaces: ProcessNamespaces,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Process {}

#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
pub struct ProcessNamespaces {
    pub mnt_id: u32,
    pub uts_id: u32,
    pub ipc_id: u32,
    pub cgroup_id: u32,
    pub pid_id: u32,
    pub pid_for_children_id: u32,
}
