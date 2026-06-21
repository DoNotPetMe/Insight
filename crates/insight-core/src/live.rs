//! Live process-memory inspection — the "scan while playing" capability.
//!
//! Process listing is cross-platform via `sysinfo`.  Memory reading uses a
//! native `/proc` backend on Linux and `ReadProcessMemory` on Windows.
//!
//! Only inspect processes you own or are authorised to analyse.  Opening a
//! [`LiveSession`] requires `authorized = true` as an explicit acknowledgement,
//! and on most systems reading another process needs elevated privileges.

#[derive(Clone)]
pub struct ProcInfo {
    pub pid: u32,
    pub name: String,
}

#[derive(Clone)]
pub struct Region {
    pub start: u64,
    pub end: u64,
    pub perms: String,
    pub path: String,
}

impl Region {
    pub fn size(&self) -> u64 {
        self.end - self.start
    }
    pub fn readable(&self) -> bool {
        self.perms.contains('r')
    }
}

pub fn list_processes() -> Vec<ProcInfo> {
    use sysinfo::System;
    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    let mut out: Vec<ProcInfo> = sys
        .processes()
        .iter()
        .map(|(pid, p)| ProcInfo {
            pid: pid.as_u32(),
            name: p.name().to_string_lossy().into_owned(),
        })
        .collect();
    out.sort_by_key(|p| p.pid);
    out
}

trait Backend {
    fn regions(&self) -> Vec<Region>;
    fn read(&self, addr: u64, len: usize) -> Vec<u8>;
}

pub struct LiveSession {
    pub pid: u32,
    backend: Box<dyn Backend>,
}

const CHUNK: usize = 1 << 20;

impl LiveSession {
    pub fn open(pid: u32, authorized: bool) -> Result<Self, String> {
        if !authorized {
            return Err("refusing to attach without authorization — only inspect \
                        processes you own or are permitted to analyse"
                .into());
        }
        let backend = make_backend(pid)?;
        Ok(Self { pid, backend })
    }

    pub fn regions(&self) -> Vec<Region> {
        self.backend.regions()
    }

    pub fn read(&self, addr: u64, len: usize) -> Vec<u8> {
        self.backend.read(addr, len)
    }

    pub fn scan_bytes(&self, needle: &[u8], limit: usize) -> Vec<u64> {
        let mut hits = Vec::new();
        if needle.is_empty() {
            return hits;
        }
        let overlap = needle.len() - 1;
        for r in self.regions() {
            if !r.readable() || r.path == "[vvar]" || r.path == "[vsyscall]" {
                continue;
            }
            let mut addr = r.start;
            while addr < r.end {
                let want = CHUNK.min((r.end - addr) as usize);
                let chunk = self.read(addr, want);
                if chunk.is_empty() {
                    break;
                }
                let mut base = 0;
                while let Some(i) = find_sub(&chunk[base..], needle) {
                    hits.push(addr + (base + i) as u64);
                    if hits.len() >= limit {
                        return hits;
                    }
                    base += i + 1;
                }
                if chunk.len() > overlap {
                    addr += (chunk.len() - overlap) as u64;
                } else {
                    addr += chunk.len() as u64;
                }
            }
        }
        hits
    }

    pub fn scan_string(&self, text: &str, limit: usize) -> Vec<u64> {
        self.scan_bytes(text.as_bytes(), limit)
    }

    pub fn scan_i32(&self, value: i32, limit: usize) -> Vec<u64> {
        self.scan_bytes(&value.to_le_bytes(), limit)
    }
}

fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ---------------------------------------------------------------------------
// Linux backend
// ---------------------------------------------------------------------------
#[cfg(target_os = "linux")]
fn make_backend(pid: u32) -> Result<Box<dyn Backend>, String> {
    let mem = std::fs::File::open(format!("/proc/{pid}/mem"))
        .map_err(|e| format!("open /proc/{pid}/mem: {e}"))?;
    Ok(Box::new(LinuxBackend { pid, mem }))
}

#[cfg(target_os = "linux")]
struct LinuxBackend {
    pid: u32,
    mem: std::fs::File,
}

#[cfg(target_os = "linux")]
impl Backend for LinuxBackend {
    fn regions(&self) -> Vec<Region> {
        let mut out = Vec::new();
        let Ok(maps) = std::fs::read_to_string(format!("/proc/{}/maps", self.pid)) else {
            return out;
        };
        for line in maps.lines() {
            let mut parts = line.split_whitespace();
            let (Some(range), Some(perms)) = (parts.next(), parts.next()) else {
                continue;
            };
            let path = parts.nth(3).unwrap_or("").to_string();
            if let Some((a, b)) = range.split_once('-') {
                if let (Ok(start), Ok(end)) =
                    (u64::from_str_radix(a, 16), u64::from_str_radix(b, 16))
                {
                    out.push(Region { start, end, perms: perms.to_string(), path });
                }
            }
        }
        out
    }

    fn read(&self, addr: u64, len: usize) -> Vec<u8> {
        use std::os::unix::fs::FileExt;
        let mut buf = vec![0u8; len];
        match self.mem.read_at(&mut buf, addr) {
            Ok(n) => {
                buf.truncate(n);
                buf
            }
            Err(_) => Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Windows backend
// ---------------------------------------------------------------------------
#[cfg(windows)]
fn make_backend(pid: u32) -> Result<Box<dyn Backend>, String> {
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };
    let handle = unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid) };
    if handle.is_null() {
        return Err(format!(
            "OpenProcess({pid}) failed — try running as Administrator"
        ));
    }
    Ok(Box::new(WinBackend { handle }))
}

#[cfg(windows)]
struct WinBackend {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl Drop for WinBackend {
    fn drop(&mut self) {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.handle) };
    }
}

#[cfg(windows)]
impl Backend for WinBackend {
    fn regions(&self) -> Vec<Region> {
        use windows_sys::Win32::System::Memory::{
            VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS,
        };
        let mut out = Vec::new();
        let mut addr: usize = 0;
        loop {
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            let n = unsafe {
                VirtualQueryEx(
                    self.handle,
                    addr as *const _,
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if n == 0 {
                break;
            }
            let base = mbi.BaseAddress as u64;
            let size = mbi.RegionSize as u64;
            let committed = mbi.State == MEM_COMMIT;
            let protect = mbi.Protect;
            let bad = protect & (PAGE_GUARD | PAGE_NOACCESS) != 0;
            if committed && !bad {
                out.push(Region {
                    start: base,
                    end: base + size,
                    perms: "r".into(),
                    path: String::new(),
                });
            }
            addr = (base + size) as usize;
            if addr == 0 {
                break;
            }
        }
        out
    }

    fn read(&self, addr: u64, len: usize) -> Vec<u8> {
        use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        let mut buf = vec![0u8; len];
        let mut read: usize = 0;
        let ok = unsafe {
            ReadProcessMemory(
                self.handle,
                addr as *const _,
                buf.as_mut_ptr() as *mut _,
                len,
                &mut read,
            )
        };
        if ok == 0 {
            return Vec::new();
        }
        buf.truncate(read);
        buf
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
fn make_backend(_pid: u32) -> Result<Box<dyn Backend>, String> {
    Err("live memory scanning is supported on Linux and Windows".into())
}
