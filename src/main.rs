mod util;

use chrono::Utc;
use clap::{error::ErrorKind, ArgAction, CommandFactory, Parser, ValueHint};
use signal_hook::consts::SIGINT;
use signal_hook::flag;
use std::cmp;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::iter;
use std::ops::Range;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use util::{encode_bin, partition_ranges};

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

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
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

struct Detection {
    index: usize,
    expected: u64,
    observed: u64,
}

struct ScanContext<'a> {
    region: Arc<Region>,
    csv: Arc<Mutex<BufWriter<File>>>,
    stats: Arc<Stats>,
    stop: Arc<AtomicBool>,
    verify_reads: usize,
    use_clflush: bool,
    bins: Option<&'a mut [u32]>,
    words_per_cell: usize,
    cells: usize,
    clamp: bool,
}

impl<'a> ScanContext<'a> {
    fn new(
        region: Arc<Region>,
        csv: Arc<Mutex<BufWriter<File>>>,
        stats: Arc<Stats>,
        stop: Arc<AtomicBool>,
        verify_reads: usize,
        use_clflush: bool,
        bins: Option<&'a mut [u32]>,
        words_per_cell: usize,
        cells: usize,
        clamp: bool,
    ) -> Self {
        Self {
            region,
            csv,
            stats,
            stop,
            verify_reads: verify_reads.max(1),
            use_clflush,
            bins,
            words_per_cell: cmp::max(1, words_per_cell),
            cells: cmp::max(1, cells),
            clamp,
        }
    }

    fn should_stop(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    fn record_detection(&self, thread_index: usize, detection: &Detection) {
        self.stats.detected.fetch_add(1, Ordering::Relaxed);
        log_event(
            &self.csv,
            thread_index,
            detection.index as u64,
            detection.expected,
            detection.observed,
            self.verify_reads,
        );
    }

    fn update_bins(&mut self, index: usize) {
        if let Some(bins) = self.bins.as_mut() {
            let slot = cmp::min(self.cells - 1, index / self.words_per_cell);
            if self.clamp {
                if bins[slot] < 9 {
                    bins[slot] += 1;
                }
            } else {
                bins[slot] = bins[slot].saturating_add(1);
            }
        }
    }

    fn increment_scanned(&self) {
        self.stats.scanned.fetch_add(1, Ordering::Relaxed);
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

#[derive(Parser, Debug)]
#[command(name = "seufinder", about = "DRAM bit-flip monitor (Rust)")]
struct CliArgs {
    #[arg(short = 'm', value_name = "GiB", default_value_t = 1)]
    gib: usize,

    #[arg(
        short = 'i',
        long = "interval",
        value_name = "SEC",
        default_value_t = 900
    )]
    interval_sec: u64,

    #[arg(short = 't', value_name = "THREADS", default_value_t = 1)]
    threads: usize,

    #[arg(long = "verify", value_name = "N", default_value_t = 2)]
    verify_reads: usize,

    #[arg(long = "clflush", action = ArgAction::SetTrue)]
    use_clflush: bool,

    #[arg(short = 'o', value_name = "FILE", value_hint = ValueHint::FilePath)]
    out_csv: Option<PathBuf>,

    #[arg(long = "iterations", value_name = "N", value_parser = clap::value_parser!(i64))]
    iterations: Option<i64>,

    #[arg(long = "lock-pages", alias = "mlock", action = ArgAction::SetTrue)]
    lock_pages: bool,

    #[arg(long = "viz-map", value_name = "PATH", value_hint = ValueHint::FilePath)]
    viz_map: Option<PathBuf>,

    #[arg(long = "viz-cols", value_name = "COLS", default_value_t = 20)]
    viz_cols: usize,

    #[arg(long = "viz-rows", value_name = "ROWS", default_value_t = 12)]
    viz_rows: usize,

    #[arg(long = "viz-unclamped", action = ArgAction::SetTrue)]
    viz_unclamped: bool,
}

impl CliArgs {
    fn into_configs(self) -> (Config, VizCfg) {
        let mut cfg = Config::default();
        cfg.gib = self.gib;
        cfg.interval_sec = self.interval_sec;
        cfg.threads = self.threads.max(1);
        cfg.verify_reads = self.verify_reads.max(1);
        cfg.use_clflush = self.use_clflush;
        if let Some(path) = self.out_csv {
            cfg.out_csv = path;
        }
        cfg.iterations =
            self.iterations
                .and_then(|value| if value > 0 { Some(value as u64) } else { None });
        cfg.lock_pages = self.lock_pages;

        let mut viz = VizCfg::default();
        viz.map_path = self.viz_map;
        viz.cols = self.viz_cols.max(1);
        viz.rows = self.viz_rows.max(1);
        viz.clamp_0_9 = !self.viz_unclamped;

        (cfg, viz)
    }
}

fn parse_args() -> Result<(Config, VizCfg), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    parse_args_from(args)
}

fn parse_args_from<I>(args: I) -> Result<(Config, VizCfg), String>
where
    I: IntoIterator<Item = String>,
{
    let args_vec = args.into_iter().collect::<Vec<_>>();
    let argv = iter::once("seufinder".to_string()).chain(args_vec.clone());
    match CliArgs::try_parse_from(argv) {
        Ok(parsed) => Ok(parsed.into_configs()),
        Err(err) => {
            let message = err.to_string();
            let needs_value_hint = matches!(
                err.kind(),
                ErrorKind::MissingRequiredArgument
                    | ErrorKind::ValueValidation
                    | ErrorKind::InvalidValue
            );

            if needs_value_hint && !message.contains("requires a value") {
                Err(format!("{}\nrequires a value", message))
            } else {
                Err(message)
            }
        }
    }
}

fn print_usage() {
    let mut cmd = CliArgs::command();
    cmd.print_long_help().expect("failed to render help");
    println!();
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

    for r in 0..rows {
        for c in 0..cols {
            let idx = r * cols + c;
            let val = bins.get(idx).copied().unwrap_or(0);
            let ch = encode_bin(val, viz.clamp_0_9);
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

    let ranges = partition_ranges(words, threads);
    let mut local_bins = if map_enabled {
        vec![vec![0u32; cells]; threads]
    } else {
        Vec::new()
    };

    let verify_reads = cfg.verify_reads.max(1);
    let use_clflush = cfg.use_clflush;
    let clamp = viz.clamp_0_9;

    thread::scope(|scope| {
        if map_enabled {
            for (t, (range, bins)) in ranges
                .iter()
                .cloned()
                .zip(local_bins.iter_mut())
                .enumerate()
            {
                if range.is_empty() {
                    continue;
                }
                let region = Arc::clone(region);
                let csv = Arc::clone(csv);
                let stats = Arc::clone(stats);
                let stop = Arc::clone(stop);
                scope.spawn(move || {
                    let ctx = ScanContext::new(
                        region,
                        csv,
                        stats,
                        stop,
                        verify_reads,
                        use_clflush,
                        Some(&mut bins[..]),
                        words_per_cell,
                        cells,
                        clamp,
                    );
                    scan_range(range, t, ctx);
                });
            }
        } else {
            for (t, range) in ranges.into_iter().enumerate() {
                if range.is_empty() {
                    continue;
                }
                let region = Arc::clone(region);
                let csv = Arc::clone(csv);
                let stats = Arc::clone(stats);
                let stop = Arc::clone(stop);
                scope.spawn(move || {
                    let ctx = ScanContext::new(
                        region,
                        csv,
                        stats,
                        stop,
                        verify_reads,
                        use_clflush,
                        None,
                        words_per_cell,
                        cells,
                        clamp,
                    );
                    scan_range(range, t, ctx);
                });
            }
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

fn scan_range(range: Range<usize>, thread_index: usize, mut ctx: ScanContext<'_>) {
    let ptr = ctx.region.as_ptr();
    for idx in range {
        if ctx.should_stop() {
            return;
        }

        if let Some(detection) = detect_flip(ptr, idx, ctx.verify_reads, ctx.use_clflush) {
            ctx.record_detection(thread_index, &detection);
            ctx.update_bins(idx);
        }

        ctx.increment_scanned();
    }
}

fn detect_flip(
    ptr: *mut u64,
    index: usize,
    verify_reads: usize,
    use_clflush: bool,
) -> Option<Detection> {
    let expected = pattern_from_index(index as u64);
    let cell = unsafe { ptr.add(index) };

    if use_clflush {
        unsafe { clflush64(cell as *const u8) };
    }

    let mut last = unsafe { std::ptr::read_volatile(cell) };
    if last == expected {
        return None;
    }

    let confirmed = (1..verify_reads).all(|_| {
        if use_clflush {
            unsafe { clflush64(cell as *const u8) };
        }
        thread::sleep(Duration::from_micros(50));
        last = unsafe { std::ptr::read_volatile(cell) };
        last != expected
    });

    if !confirmed {
        return None;
    }

    unsafe { std::ptr::write_volatile(cell, expected) };

    Some(Detection {
        index,
        expected,
        observed: last,
    })
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
    for (idx, slot) in data.iter_mut().enumerate() {
        *slot = pattern_from_index(idx as u64);
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn parse(args: &[&str]) -> (Config, VizCfg) {
        let owned = args.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        parse_args_from(owned).expect("failed to parse args")
    }

    #[test]
    fn parse_args_defaults_match_config() {
        let (cfg, viz) = parse(&[]);
        assert_eq!(cfg.gib, 1);
        assert_eq!(cfg.interval_sec, 900);
        assert_eq!(cfg.threads, 1);
        assert_eq!(cfg.verify_reads, 2);
        assert_eq!(cfg.iterations, None);
        assert!(!cfg.use_clflush);
        assert!(!cfg.lock_pages);
        assert!(viz.map_path.is_none());
        assert_eq!(viz.cols, 20);
        assert_eq!(viz.rows, 12);
        assert!(viz.clamp_0_9);
    }

    #[test]
    fn parse_args_overrides_values() {
        let (cfg, viz) = parse(&[
            "-m",
            "3",
            "-i",
            "60",
            "-t",
            "4",
            "--verify",
            "5",
            "--clflush",
            "-o",
            "custom.csv",
            "--iterations",
            "7",
            "--lock-pages",
            "--viz-map",
            "viz.log",
            "--viz-cols",
            "10",
            "--viz-rows",
            "8",
            "--viz-unclamped",
        ]);

        assert_eq!(cfg.gib, 3);
        assert_eq!(cfg.interval_sec, 60);
        assert_eq!(cfg.threads, 4);
        assert_eq!(cfg.verify_reads, 5);
        assert!(cfg.use_clflush);
        assert_eq!(cfg.out_csv, PathBuf::from("custom.csv"));
        assert_eq!(cfg.iterations, Some(7));
        assert!(cfg.lock_pages);
        assert_eq!(viz.map_path, Some(PathBuf::from("viz.log")));
        assert_eq!(viz.cols, 10);
        assert_eq!(viz.rows, 8);
        assert!(!viz.clamp_0_9);
    }

    #[test]
    fn parse_args_requires_values() {
        let err = parse_args_from(vec!["-m".to_string()]).unwrap_err();
        assert!(err.contains("requires a value"));
    }

    #[test]
    fn pattern_generator_matches_expected_values() {
        assert_eq!(pattern_from_index(0), 0x0f4a_01b8_4757_d994);
        assert_eq!(pattern_from_index(1), 0x84ac_eac4_89e9_99d5);
        assert_eq!(pattern_from_index(123_456), 0x5352_b57d_463f_c5b8);
    }

    #[test]
    fn viz_write_frame_clamps_values() {
        let path = std::env::temp_dir().join(format!(
            "seufinder_test_{}_{}_clamp.txt",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_file(&path);
        let viz = VizCfg {
            map_path: Some(path.clone()),
            cols: 3,
            rows: 2,
            clamp_0_9: true,
        };
        let bins = vec![0, 1, 9, 10, 11, 12];
        viz_write_frame(&viz, &bins).expect("write frame");

        let content = fs::read_to_string(&path).expect("read viz file");
        assert!(content.contains("#19"));
        assert!(content.contains("999"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn viz_write_frame_unclamped_uses_alphabet() {
        let path = std::env::temp_dir().join(format!(
            "seufinder_test_{}_{}_unclamp.txt",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_file(&path);
        let viz = VizCfg {
            map_path: Some(path.clone()),
            cols: 4,
            rows: 1,
            clamp_0_9: false,
        };
        let bins = vec![0, 9, 10, 36];
        viz_write_frame(&viz, &bins).expect("write frame");

        let content = fs::read_to_string(&path).expect("read viz file");
        assert!(content.contains("#9A*"));
        let _ = fs::remove_file(path);
    }
}
