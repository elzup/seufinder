use std::ops::Range;

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
