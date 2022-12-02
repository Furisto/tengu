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
pub struct BtfEvent {
    pub key: u64,
    pub kind: BtfEventKind,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BtfEvent {}

#[derive(Copy, Clone)]
pub enum BtfEventKind {
    Cgroup,
    Process
}

pub struct CgroupEvent {
    pub operation: CGroupOperation,
    pub id: u64,
    
}

pub enum CGroupOperation {
    Add,
    Remove,
    Attach,
    Detach,
}

pub struct ProcessEvent {
    pub id:u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Process {
    pub id: i32,
    pub parent_id: i32,
    pub namespaces: ProcessNamespaces,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Process {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessNamespaces {
    pub mnt_id: u32,
    pub uts_id: u32,
    pub ipc_id: u32,
    pub cgroup_id: u32,
    pub pid_id: u32,
    pub pid_for_children_id: u32,
}


