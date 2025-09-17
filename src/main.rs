use chrono::Utc;
use signal_hook::consts::SIGINT;
use signal_hook::flag;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use signal_hook::consts::SIGTERM;

#[cfg(unix)]
fn lock_pages(ptr: *mut u8, bytes: usize) -> io::Result<()> {
    let res = unsafe { libc::mlock(ptr as *const _, bytes) };
    if res == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn lock_pages(ptr: *mut u8, bytes: usize) -> io::Result<()> {
    use windows_sys::Win32::System::Memory::VirtualLock;
    let ok = unsafe { VirtualLock(ptr as *mut _, bytes) };
    if ok != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(all(not(unix), not(windows)))]
fn lock_pages(_ptr: *mut u8, _bytes: usize) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Other,
        "page locking not supported on this platform",
    ))
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
unsafe fn clflush64(ptr: *const u8) {
    #[cfg(target_arch = "x86")]
    {
        core::arch::x86::_mm_clflush(ptr);
    }
    #[cfg(target_arch = "x86_64")]
    {
        core::arch::x86_64::_mm_clflush(ptr);
    }
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
#[inline(always)]
unsafe fn clflush64(_ptr: *const u8) {}

#[derive(Clone)]
struct Config {
    gib: usize,
    interval_sec: u64,
    threads: usize,
    verify_reads: usize,
    use_clflush: bool,
    out_csv: PathBuf,
    iterations: Option<u64>,
    lock_pages: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            gib: 1,
            interval_sec: 900,
            threads: 1,
            verify_reads: 2,
            use_clflush: false,
            out_csv: PathBuf::from("seufinder.csv"),
            iterations: None,
            lock_pages: false,
        }
    }
}

#[derive(Clone)]
struct VizCfg {
    map_path: Option<PathBuf>,
    cols: usize,
    rows: usize,
    clamp_0_9: bool,
}

impl Default for VizCfg {
    fn default() -> Self {
        Self {
            map_path: None,
            cols: 20,
            rows: 12,
            clamp_0_9: true,
        }
    }
}

struct Region {
    ptr: *mut u64,
    words: usize,
    capacity: usize,
}

unsafe impl Send for Region {}
unsafe impl Sync for Region {}

impl Region {
    fn from_vec(mut data: Vec<u64>) -> Self {
        let ptr = data.as_mut_ptr();
        let words = data.len();
        let capacity = data.capacity();
        std::mem::forget(data);
        Self {
            ptr,
            words,
            capacity,
        }
    }

    #[inline]
    fn as_ptr(&self) -> *mut u64 {
        self.ptr
    }

    #[inline]
    fn words(&self) -> usize {
        self.words
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        unsafe {
            let _ = Vec::from_raw_parts(self.ptr, self.words, self.capacity);
        }
    }
}

struct Stats {
    scanned: AtomicU64,
    detected: AtomicU64,
}

impl Stats {
    fn new() -> Self {
        Self {
            scanned: AtomicU64::new(0),
            detected: AtomicU64::new(0),
        }
    }
}

fn now_iso8601_utc() -> String {
    let now = Utc::now();
    now.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

fn pattern_from_index(idx: u64) -> u64 {
    let mut x = idx.wrapping_add(0x9E37_79B9_7F4A_7C15u64);
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccdu64);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53u64);
    x ^= x >> 33;
    x ^ 0xAAAA_AAAA_AAAA_AAAAu64 ^ (x << 1)
}

fn parse_args() -> Result<(Config, VizCfg), String> {
    let mut cfg = Config::default();
    let mut viz = VizCfg::default();

    let mut args = env::args().skip(1).collect::<Vec<_>>();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "-m" => {
                i += 1;
                let val = args.get(i).ok_or("-m requires a value")?;
                cfg.gib = val.parse().map_err(|_| "invalid GiB value".to_string())?;
            }
            "-i" => {
                i += 1;
                let val = args.get(i).ok_or("-i requires a value")?;
                cfg.interval_sec = val.parse().map_err(|_| "invalid interval".to_string())?;
            }
            "-t" => {
                i += 1;
                let val = args.get(i).ok_or("-t requires a value")?;
                cfg.threads = val
                    .parse()
                    .map_err(|_| "invalid thread count".to_string())?;
            }
            "--verify" => {
                i += 1;
                let val = args.get(i).ok_or("--verify requires a value")?;
                cfg.verify_reads = val
                    .parse()
                    .map_err(|_| "invalid verify count".to_string())?;
            }
            "--clflush" => {
                cfg.use_clflush = true;
            }
            "-o" => {
                i += 1;
                let val = args.get(i).ok_or("-o requires a value")?;
                cfg.out_csv = PathBuf::from(val);
            }
            "--iterations" => {
                i += 1;
                let val = args.get(i).ok_or("--iterations requires a value")?;
                let parsed: i64 = val.parse().map_err(|_| "invalid iterations".to_string())?;
                if parsed > 0 {
                    cfg.iterations = Some(parsed as u64);
                } else {
                    cfg.iterations = None;
                }
            }
            "--mlock" | "--lock-pages" => {
                cfg.lock_pages = true;
            }
            "--viz-map" => {
                i += 1;
                let val = args.get(i).ok_or("--viz-map requires a value")?;
                viz.map_path = Some(PathBuf::from(val));
            }
            "--viz-cols" => {
                i += 1;
                let val = args.get(i).ok_or("--viz-cols requires a value")?;
                viz.cols = val.parse().map_err(|_| "invalid viz cols".to_string())?;
            }
            "--viz-rows" => {
                i += 1;
                let val = args.get(i).ok_or("--viz-rows requires a value")?;
                viz.rows = val.parse().map_err(|_| "invalid viz rows".to_string())?;
            }
            "--viz-unclamped" => {
                viz.clamp_0_9 = false;
            }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            other => {
                return Err(format!("unknown option: {}", other));
            }
        }
        i += 1;
    }

    if cfg.threads == 0 {
        cfg.threads = 1;
    }
    if cfg.verify_reads == 0 {
        cfg.verify_reads = 1;
    }

    Ok((cfg, viz))
}

fn print_usage() {
    println!(
        "seufinder-rs - DRAM bit-flip monitor (Rust)\n\
Usage: seufinder-rs [options]\n\
  -m <GiB>           Memory to occupy (default 1)\n\
  -i <sec>           Scan interval seconds (default 900=15min)\n\
  -t <threads>       Reader threads (default 1)\n\
  --verify <N>       Re-read count per mismatch (default 2)\n\
  --clflush          Use CLFLUSH before reads (x86/x86_64 only)\n\
  -o <csv>           CSV output path (default seufinder.csv)\n\
  --iterations <K>   Run exactly K scans (default infinite)\n\
  --mlock            Try to lock pages in memory\n\
  --viz-map <path>   Append ASCII grid to this file each scan\n\
  --viz-cols <n>     Grid columns (default 20)\n\
  --viz-rows <n>     Grid rows (default 12)\n\
  --viz-unclamped    Do not clamp counts to 0-9 (>=10 shown as A..Z)\n\
  -h, --help         Show this help"
    );
}

fn sleep_until_or_stop(stop: &AtomicBool, deadline: Instant) {
    while !stop.load(Ordering::Relaxed) {
        if Instant::now() >= deadline {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn log_event(
    csv: &Arc<Mutex<BufWriter<File>>>,
    tid: usize,
    idx: u64,
    expected: u64,
    observed: u64,
    repro_reads: usize,
) {
    if let Ok(mut guard) = csv.lock() {
        let _ = writeln!(
            guard,
            "{},{},{},{:016x},{:016x},{:016x},{}",
            now_iso8601_utc(),
            tid,
            idx,
            expected,
            observed,
            expected ^ observed,
            repro_reads
        );
    }
}

fn viz_write_frame(viz: &VizCfg, bins: &[u32]) -> io::Result<()> {
    let path = match &viz.map_path {
        Some(p) => p,
        None => return Ok(()),
    };
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{}", now_iso8601_utc())?;

    let cols = viz.cols;
    let rows = viz.rows;
    let clamp = viz.clamp_0_9;

    for r in 0..rows {
        for c in 0..cols {
            let idx = r * cols + c;
            let val = bins.get(idx).copied().unwrap_or(0);
            let ch = if clamp {
                if val == 0 {
                    '#'
                } else if val >= 9 {
                    '9'
                } else {
                    char::from(b'0' + val as u8)
                }
            } else {
                if val == 0 {
                    '#'
                } else if val <= 9 {
                    char::from(b'0' + val as u8)
                } else if val <= 35 {
                    char::from(b'A' + (val as u8 - 10))
                } else {
                    '*'
                }
            };
            let _ = write!(file, "{}", ch);
        }
        writeln!(file)?;
    }
    writeln!(file)?;
    file.flush()
}

fn scan_once(
    region: &Arc<Region>,
    cfg: &Config,
    viz: &VizCfg,
    csv: &Arc<Mutex<BufWriter<File>>>,
    stats: &Arc<Stats>,
    stop: &Arc<AtomicBool>,
) -> io::Result<()> {
    let threads = cfg.threads.max(1);
    let words = region.words();
    let map_enabled = viz.map_path.is_some();
    let cells = if map_enabled {
        std::cmp::max(1, viz.cols * viz.rows)
    } else {
        0
    };
    let words_per_cell = if map_enabled {
        std::cmp::max(1, words / cells)
    } else {
        1
    };

    let mut local_bins = if map_enabled {
        vec![vec![0u32; cells]; threads]
    } else {
        Vec::new()
    };

    let verify_reads = cfg.verify_reads.max(1);
    let use_clflush = cfg.use_clflush;
    let clamp = viz.clamp_0_9;

    thread::scope(|scope| {
        for t in 0..threads {
            let begin = t * (words / threads);
            let end = if t == threads - 1 {
                words
            } else {
                begin + (words / threads)
            };
            let region = Arc::clone(region);
            let csv = Arc::clone(csv);
            let stats = Arc::clone(stats);
            let stop = Arc::clone(stop);
            let bins_ptr = if map_enabled {
                Some(&mut local_bins[t] as *mut Vec<u32>)
            } else {
                None
            };

            scope.spawn(move || {
                let ptr = region.as_ptr();
                for i in begin..end {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    let exp = pattern_from_index(i as u64);
                    if use_clflush {
                        unsafe { clflush64(ptr.add(i) as *const u8) };
                    }
                    let v1 = unsafe { std::ptr::read_volatile(ptr.add(i)) };
                    if v1 != exp {
                        let mut mismatches = 0usize;
                        let mut last = v1;
                        for _ in 1..verify_reads {
                            if use_clflush {
                                unsafe { clflush64(ptr.add(i) as *const u8) };
                            }
                            thread::sleep(Duration::from_micros(50));
                            let vr = unsafe { std::ptr::read_volatile(ptr.add(i)) };
                            last = vr;
                            if vr != exp {
                                mismatches += 1;
                            }
                        }
                        if mismatches == verify_reads - 1 {
                            stats.detected.fetch_add(1, Ordering::Relaxed);
                            log_event(&csv, t, i as u64, exp, last, verify_reads);
                            unsafe { std::ptr::write_volatile(ptr.add(i), exp) };
                            if let Some(bp) = bins_ptr {
                                unsafe {
                                    let bins = &mut *bp;
                                    let idx = std::cmp::min(cells - 1, i / words_per_cell);
                                    if clamp {
                                        if bins[idx] < 9 {
                                            bins[idx] += 1;
                                        }
                                    } else {
                                        bins[idx] = bins[idx].saturating_add(1);
                                    }
                                }
                            }
                        }
                    }
                    stats.scanned.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
    });

    if map_enabled {
        let mut final_bins = vec![0u32; cells];
        for bins in &local_bins {
            for (idx, &val) in bins.iter().enumerate() {
                if clamp {
                    let sum = final_bins[idx] + val;
                    final_bins[idx] = std::cmp::min(sum, 9);
                } else {
                    final_bins[idx] = final_bins[idx].saturating_add(val);
                }
            }
        }
        viz_write_frame(viz, &final_bins)?;
    }

    if let Ok(mut guard) = csv.lock() {
        let _ = guard.flush();
    }
    Ok(())
}

fn main() {
    let (cfg, viz) = match parse_args() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {}", e);
            print_usage();
            std::process::exit(1);
        }
    };

    let stop = Arc::new(AtomicBool::new(false));
    flag::register(SIGINT, Arc::clone(&stop)).expect("failed to register SIGINT handler");
    #[cfg(unix)]
    flag::register(SIGTERM, Arc::clone(&stop)).expect("failed to register SIGTERM handler");

    let bytes = match cfg.gib.checked_mul(1usize << 30) {
        Some(v) => v,
        None => {
            eprintln!("[ERR] invalid memory size");
            std::process::exit(2);
        }
    };
    if bytes % std::mem::size_of::<u64>() != 0 {
        eprintln!("[ERR] memory size must be multiple of 8 bytes");
        std::process::exit(2);
    }

    let words = bytes / std::mem::size_of::<u64>();
    eprintln!("[INFO] Allocating {} GiB ({} bytes)...", cfg.gib, bytes);
    let mut data = vec![0u64; words];

    if cfg.lock_pages {
        match lock_pages(data.as_mut_ptr() as *mut u8, bytes) {
            Ok(_) => eprintln!("[INFO] pages locked"),
            Err(e) => eprintln!("[WARN] page lock failed: {}", e),
        }
    }

    eprintln!("[INFO] Initializing pattern...");
    let init_threads = cfg.threads.max(1);
    thread::scope(|scope| {
        for t in 0..init_threads {
            let total = words;
            let chunk = total / init_threads;
            let begin = t * chunk;
            let end = if t == init_threads - 1 {
                total
            } else {
                begin + chunk
            };
            let slice = &mut data[begin..end];
            scope.spawn(move || {
                for (offset, slot) in slice.iter_mut().enumerate() {
                    let idx = begin + offset;
                    *slot = pattern_from_index(idx as u64);
                }
            });
        }
    });

    let region = Arc::new(Region::from_vec(data));

    let csv_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&cfg.out_csv)
        .unwrap_or_else(|e| {
            eprintln!("[ERR] cannot open csv {}: {}", cfg.out_csv.display(), e);
            std::process::exit(3);
        });
    let mut csv_writer = BufWriter::new(csv_file);
    writeln!(
        csv_writer,
        "timestamp_utc,thread,index,expected_hex,observed_hex,xor_hex,repro_reads"
    )
    .expect("failed to write CSV header");
    csv_writer.flush().expect("failed to flush CSV header");
    let csv = Arc::new(Mutex::new(csv_writer));

    let stats = Arc::new(Stats::new());

    eprintln!(
        "[INFO] Start monitoring: interval={}s threads={} verify={} clflush={} viz={}",
        cfg.interval_sec,
        cfg.threads,
        cfg.verify_reads,
        if cfg.use_clflush { "on" } else { "off" },
        if viz.map_path.is_some() { "on" } else { "off" }
    );

    let mut iter = 0u64;
    while !stop.load(Ordering::Relaxed) {
        let start = Instant::now();
        if let Err(e) = scan_once(&region, &cfg, &viz, &csv, &stats, &stop) {
            eprintln!("[ERR] scan error: {}", e);
            break;
        }
        iter += 1;
        eprintln!(
            "[STAT] iter={} scanned={} words, detected={}",
            iter,
            stats.scanned.load(Ordering::Relaxed),
            stats.detected.load(Ordering::Relaxed)
        );

        if let Some(limit) = cfg.iterations {
            if iter >= limit {
                break;
            }
        }

        let next_deadline = start + Duration::from_secs(cfg.interval_sec);
        sleep_until_or_stop(&stop, next_deadline);
    }

    eprintln!("[INFO] bye");
}
