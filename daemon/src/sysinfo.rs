//! Host resource information (CPU, memory, disk, uptime) for the dashboard.
//!
//! Everything is read from procfs/sysfs and `statvfs`, all of which stay
//! readable under the daemon's `ProtectSystem=strict` sandbox.

use keystone_core::{DiskUsage, SystemInfo};
use std::fs;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Minimum spacing between CPU samples, so several dashboards polling at once
/// don't shrink the measurement window to noise.
const CPU_SAMPLE_MIN_INTERVAL: Duration = Duration::from_secs(1);

/// Filesystems worth showing; everything else is virtual or per-service tmpfs.
const DISK_FS_TYPES: &[&str] = &[
    "ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "zfs", "vfat", "exfat", "ntfs3",
];

/// Sensor chips whose temperature reflects the CPU package.
const CPU_HWMON_NAMES: &[&str] = &[
    "coretemp",
    "k10temp",
    "zenpower",
    "cpu_thermal",
    "soc_thermal",
    "cpu-thermal",
];

#[derive(Clone, Copy)]
struct CpuSample {
    busy: u64,
    total: u64,
}

struct CpuState {
    sample: CpuSample,
    taken: Instant,
    usage_percent: Option<f64>,
}

static CPU_STATE: OnceLock<Mutex<Option<CpuState>>> = OnceLock::new();

/// Collect a snapshot of the host's resources. Blocking; call from a blocking task.
pub fn collect() -> SystemInfo {
    let read = |path: &str| fs::read_to_string(path).unwrap_or_default();

    let (memory_total, memory_available, swap_total, swap_free) =
        parse_meminfo(&read("/proc/meminfo"));
    let (cpu_model, cpu_count) = parse_cpuinfo(&read("/proc/cpuinfo"));

    SystemInfo {
        hostname: read("/proc/sys/kernel/hostname").trim().to_owned(),
        kernel: read("/proc/sys/kernel/osrelease").trim().to_owned(),
        uptime_secs: parse_uptime(&read("/proc/uptime")),
        load_average: parse_loadavg(&read("/proc/loadavg")),
        cpu_model,
        cpu_count,
        cpu_usage_percent: sample_cpu_usage(&read("/proc/stat")),
        memory_total_bytes: memory_total,
        memory_used_bytes: memory_total.saturating_sub(memory_available),
        swap_total_bytes: swap_total,
        swap_used_bytes: swap_total.saturating_sub(swap_free),
        disks: collect_disks(&read("/proc/mounts")),
        cpu_temperature_c: read_cpu_temperature(),
    }
}

fn sample_cpu_usage(proc_stat: &str) -> Option<f64> {
    let current = parse_cpu_stat(proc_stat)?;
    let mut guard = CPU_STATE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let now = Instant::now();

    let usage = match guard.as_ref() {
        Some(prev) if now.duration_since(prev.taken) < CPU_SAMPLE_MIN_INTERVAL => {
            return prev.usage_percent;
        }
        Some(prev) => cpu_usage_between(prev.sample, current).or(prev.usage_percent),
        None => None,
    };
    *guard = Some(CpuState {
        sample: current,
        taken: now,
        usage_percent: usage,
    });
    usage
}

fn cpu_usage_between(prev: CpuSample, current: CpuSample) -> Option<f64> {
    let total = current.total.checked_sub(prev.total).filter(|t| *t > 0)?;
    let busy = current.busy.saturating_sub(prev.busy);
    Some((busy as f64 / total as f64 * 100.0).clamp(0.0, 100.0))
}

/// Aggregate `cpu` line of `/proc/stat`: user nice system idle iowait irq softirq steal ...
fn parse_cpu_stat(text: &str) -> Option<CpuSample> {
    let line = text.lines().find(|l| l.starts_with("cpu "))?;
    let fields: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .take(8)
        .filter_map(|f| f.parse().ok())
        .collect();
    if fields.len() < 4 {
        return None;
    }
    let total: u64 = fields.iter().sum();
    let idle = fields[3] + fields.get(4).copied().unwrap_or(0);
    Some(CpuSample {
        busy: total.saturating_sub(idle),
        total,
    })
}

/// Returns (memory total, memory available, swap total, swap free) in bytes.
fn parse_meminfo(text: &str) -> (u64, u64, u64, u64) {
    let field = |name: &str| -> u64 {
        text.lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix(':'))
            .and_then(|rest| rest.split_whitespace().next()?.parse::<u64>().ok())
            .map(|kib| kib * 1024)
            .unwrap_or(0)
    };
    let total = field("MemTotal");
    // Old kernels lack MemAvailable; free memory alone is a safe lower bound.
    let available = match field("MemAvailable") {
        0 => field("MemFree"),
        v => v,
    };
    (total, available, field("SwapTotal"), field("SwapFree"))
}

fn parse_cpuinfo(text: &str) -> (Option<String>, u32) {
    let count = text
        .lines()
        .filter(|l| l.starts_with("processor") && l.contains(':'))
        .count() as u32;
    let model = text
        .lines()
        .find(|l| l.starts_with("model name"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|m| !m.is_empty());
    (model, count)
}

fn parse_uptime(text: &str) -> u64 {
    text.split_whitespace()
        .next()
        .and_then(|v| v.parse::<f64>().ok())
        .map(|s| s as u64)
        .unwrap_or(0)
}

fn parse_loadavg(text: &str) -> [f64; 3] {
    let mut out = [0.0; 3];
    for (slot, value) in out.iter_mut().zip(text.split_whitespace()) {
        *slot = value.parse().unwrap_or(0.0);
    }
    out
}

/// `/proc/mounts` escapes spaces and similar as octal (`\040`).
fn unescape_mount_field(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    let mut chars = field.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let digits: String = chars.clone().take(3).collect();
            if digits.len() == 3
                && let Ok(code) = u8::from_str_radix(&digits, 8)
            {
                out.push(code as char);
                chars.nth(2);
                continue;
            }
        }
        out.push(c);
    }
    out
}

/// Real, distinct block-device filesystems as (device, mount point), first mount wins.
/// Bind mounts and btrfs subvolumes share a device, and the daemon's sandbox adds
/// several of those, so they collapse into one entry.
fn parse_disk_mounts(proc_mounts: &str) -> Vec<(String, String)> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for line in proc_mounts.lines() {
        let mut parts = line.split_whitespace();
        let (Some(device), Some(mount), Some(fs_type)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if !DISK_FS_TYPES.contains(&fs_type) || !seen.insert(device.to_owned()) {
            continue;
        }
        out.push((device.to_owned(), unescape_mount_field(mount)));
    }
    out
}

fn collect_disks(proc_mounts: &str) -> Vec<DiskUsage> {
    parse_disk_mounts(proc_mounts)
        .into_iter()
        .filter_map(|(_, mount_point)| {
            let stat = nix::sys::statvfs::statvfs(mount_point.as_str()).ok()?;
            let block = stat.fragment_size() as u64;
            let total = stat.blocks() as u64 * block;
            if total == 0 {
                return None;
            }
            let used = total.saturating_sub(stat.blocks_free() as u64 * block);
            Some(DiskUsage {
                mount_point,
                total_bytes: total,
                used_bytes: used,
            })
        })
        .collect()
}

fn read_cpu_temperature() -> Option<f64> {
    let mut hottest: Option<f64> = None;
    for chip in fs::read_dir("/sys/class/hwmon").ok()?.flatten() {
        let dir = chip.path();
        let name = fs::read_to_string(dir.join("name")).unwrap_or_default();
        if !CPU_HWMON_NAMES.contains(&name.trim()) {
            continue;
        }
        for entry in fs::read_dir(&dir).ok()?.flatten() {
            let file = entry.file_name().to_string_lossy().into_owned();
            if !(file.starts_with("temp") && file.ends_with("_input")) {
                continue;
            }
            if let Some(celsius) = fs::read_to_string(entry.path())
                .ok()
                .and_then(|v| v.trim().parse::<f64>().ok())
                .map(|milli| milli / 1000.0)
                .filter(|c| (1.0..150.0).contains(c))
            {
                hottest = Some(hottest.map_or(celsius, |h| h.max(celsius)));
            }
        }
    }
    hottest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meminfo_derives_used_from_available() {
        let text = "MemTotal:       16000000 kB\nMemFree:         1000000 kB\nMemAvailable:    8000000 kB\nSwapTotal:       2000000 kB\nSwapFree:        1500000 kB\n";
        let (total, available, swap_total, swap_free) = parse_meminfo(text);
        assert_eq!(total, 16_000_000 * 1024);
        assert_eq!(available, 8_000_000 * 1024);
        assert_eq!(swap_total - swap_free, 500_000 * 1024);
    }

    #[test]
    fn meminfo_falls_back_to_free_without_available() {
        let (_, available, _, _) = parse_meminfo("MemTotal: 100 kB\nMemFree: 40 kB\n");
        assert_eq!(available, 40 * 1024);
    }

    #[test]
    fn cpu_usage_is_busy_share_of_delta() {
        let a = parse_cpu_stat("cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 1 1 1 1\n").unwrap();
        let b = parse_cpu_stat("cpu  150 0 150 900 0 0 0 0 0 0\n").unwrap();
        // 100 busy of 200 elapsed.
        assert_eq!(cpu_usage_between(a, b), Some(50.0));
        assert_eq!(cpu_usage_between(b, b), None);
    }

    #[test]
    fn cpu_iowait_counts_as_idle() {
        let s = parse_cpu_stat("cpu  10 0 10 70 10 0 0 0\n").unwrap();
        assert_eq!((s.busy, s.total), (20, 100));
    }

    #[test]
    fn cpuinfo_counts_processors_and_normalises_model() {
        let text = "processor\t: 0\nmodel name\t: Intel(R)  N100\nprocessor\t: 1\nmodel name\t: Intel(R)  N100\n";
        assert_eq!(parse_cpuinfo(text), (Some("Intel(R) N100".to_owned()), 2));
    }

    #[test]
    fn uptime_and_loadavg_parse() {
        assert_eq!(parse_uptime("12345.67 99999.00\n"), 12345);
        assert_eq!(
            parse_loadavg("0.52 0.40 0.30 1/200 999\n"),
            [0.52, 0.40, 0.30]
        );
        assert_eq!(parse_loadavg(""), [0.0; 3]);
    }

    #[test]
    fn disk_mounts_dedupe_by_device_and_skip_virtual_filesystems() {
        let mounts = "\
/dev/sda2 / ext4 rw 0 0
tmpfs /run tmpfs rw 0 0
/dev/sda2 /etc/caddy ext4 rw 0 0
/dev/sda1 /boot vfat rw 0 0
/dev/sdb1 /mnt/with\\040space xfs rw 0 0
proc /proc proc rw 0 0
";
        assert_eq!(
            parse_disk_mounts(mounts),
            vec![
                ("/dev/sda2".to_owned(), "/".to_owned()),
                ("/dev/sda1".to_owned(), "/boot".to_owned()),
                ("/dev/sdb1".to_owned(), "/mnt/with space".to_owned()),
            ]
        );
    }
}
