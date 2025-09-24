use std::ops::Range;
use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::{Duration, Instant};

pub fn partition_ranges(total: usize, parts: usize) -> Vec<Range<usize>> {
    if parts == 0 {
        return vec![0..0];
    }

    let mut ranges = Vec::with_capacity(parts);
    let base = total / parts;
    let remainder = total % parts;
    let mut start = 0usize;

    for idx in 0..parts {
        let mut end = start + base;
        if idx < remainder {
            end += 1;
        }
        end = std::cmp::min(end, total);
        ranges.push(start..end);
        start = end;
    }

    ranges
}

pub fn encode_bin(val: u32, clamp: bool) -> char {
    if clamp {
        match val {
            0 => '#',
            1..=8 => char::from(b'0' + val as u8),
            _ => '9',
        }
    } else {
        match val {
            0 => '#',
            1..=9 => char::from(b'0' + val as u8),
            10..=35 => char::from(b'A' + (val as u8 - 10)),
            _ => '*',
        }
    }
}

pub fn pattern_from_index(idx: u64) -> u64 {
    let mut x = idx.wrapping_add(0x9E37_79B9_7F4A_7C15u64);
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccdu64);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53u64);
    x ^= x >> 33;
    x ^ 0xAAAA_AAAA_AAAA_AAAAu64 ^ (x << 1)
}

pub fn sleep_until_or_stop(stop: &AtomicBool, deadline: Instant) {
    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        if Instant::now() >= deadline {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
}
