//! Command-line driver for the Local Tag Scan baselines. Each role runs as its own process so its
//! CPU time and peak memory are measured separately. Every subcommand prints one JSON line.
//!
//!   tagscan keygen      [--scheme S] --out DIR
//!   tagscan build-board [--scheme S] --n N --pk FILE --pertinent I[,J...] --out FILE [--others 1024]
//!   tagscan scan        [--scheme S] --sk FILE --board FILE [--threads 1]
//!
//! S is x25519 (x25519-dalek; the default, used by E2), x25519-awslc, mlkem512 or mlkem768.

use std::collections::HashMap;
use std::fs;
use std::time::Instant;

use tag_scan::binding_for_index;
use tag_scan::schemes::{keygen, Receiver, Recipient, Scheme};

struct Usage {
    cpu_s: f64,
    maxrss_kb: i64,
}

fn rusage() -> Usage {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    assert_eq!(rc, 0, "getrusage failed");
    let tv = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 * 1e-6;
    Usage { cpu_s: tv(ru.ru_utime) + tv(ru.ru_stime), maxrss_kb: ru.ru_maxrss }
}

fn args() -> (String, HashMap<String, String>) {
    let mut it = std::env::args().skip(1);
    let cmd = it.next().unwrap_or_default();
    let mut kv = HashMap::new();
    while let Some(k) = it.next() {
        let v = it.next().unwrap_or_else(|| panic!("missing value for {k}"));
        kv.insert(k.trim_start_matches("--").to_string(), v);
    }
    (cmd, kv)
}

fn read(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

fn main() {
    let (cmd, kv) = args();
    let get = |k: &str| kv.get(k).unwrap_or_else(|| panic!("--{k} is required")).clone();
    let scheme_name = kv.get("scheme").map(String::as_str).unwrap_or("x25519");
    let scheme = Scheme::parse(scheme_name).unwrap_or_else(|| panic!("unknown --scheme {scheme_name}"));
    let s = scheme.name();
    match cmd.as_str() {
        "keygen" => {
            let dir = get("out");
            fs::create_dir_all(&dir).unwrap();
            let u0 = rusage();
            let t0 = Instant::now();
            let (sk, pk) = keygen(scheme);
            let wall = t0.elapsed().as_secs_f64();
            let u1 = rusage();
            fs::write(format!("{dir}/sk.bin"), &sk).unwrap();
            fs::write(format!("{dir}/pk.bin"), &pk).unwrap();
            println!(
                "{{\"tool\":\"tagscan\",\"variant\":\"{s}\",\"phase\":\"receiver_keygen\",\"wall_s\":{wall:.9},\"cpu_s\":{:.6},\"maxrss_kb\":{},\"pk_bytes\":{},\"sk_bytes\":{}}}",
                u1.cpu_s - u0.cpu_s,
                u1.maxrss_kb,
                pk.len(),
                sk.len()
            );
        }
        "build-board" => {
            let n: u64 = get("n").parse().unwrap();
            let to = Recipient::from_public(scheme, &read(&get("pk")));
            let pertinent: Vec<u64> = get("pertinent")
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.parse().unwrap())
                .collect();
            assert!(pertinent.iter().all(|&i| i < n), "pertinent index out of range");
            let others_n: usize = kv.get("others").map(|s| s.parse().unwrap()).unwrap_or(1024);
            // Other receivers' public keys. Each entry still gets its own fresh sender randomness.
            let others: Vec<Recipient> =
                (0..others_n).map(|_| Recipient::from_public(scheme, &keygen(scheme).1)).collect();
            let el = scheme.entry_len();
            let mut board = Vec::with_capacity(n as usize * el);
            let u0 = rusage();
            let t0 = Instant::now();
            for i in 0..n {
                let r = if pertinent.contains(&i) { &to } else { &others[i as usize % others_n] };
                let e = r.make_entry(&binding_for_index(i)).expect("contributory receiver key");
                board.extend_from_slice(&e);
            }
            let wall = t0.elapsed().as_secs_f64();
            let u1 = rusage();
            let out = get("out");
            fs::write(&out, &board).unwrap();
            let bytes = fs::metadata(&out).unwrap().len();
            println!(
                "{{\"tool\":\"tagscan\",\"variant\":\"{s}\",\"phase\":\"sender_build_board\",\"n\":{n},\"wall_s\":{wall:.6},\"cpu_s\":{:.6},\"sender_us_per_entry\":{:.3},\"maxrss_kb\":{},\"board_bytes\":{bytes},\"entry_bytes\":{el}}}",
                u1.cpu_s - u0.cpu_s,
                wall / n as f64 * 1e6,
                u1.maxrss_kb
            );
        }
        "scan" => {
            let rx = Receiver::from_secret(scheme, &read(&get("sk")));
            let threads: usize = kv.get("threads").map(|s| s.parse().unwrap()).unwrap_or(1);
            let path = get("board");
            let t_load = Instant::now();
            let board = fs::read(&path).unwrap();
            let load_s = t_load.elapsed().as_secs_f64();
            let el = scheme.entry_len();
            assert_eq!(board.len() % el, 0, "board is not a whole number of entries");
            let n = board.len() / el;
            let u0 = rusage();
            let t0 = Instant::now();
            let matches = rx.scan_parallel(&board, threads);
            let wall = t0.elapsed().as_secs_f64();
            let u1 = rusage();
            let m: Vec<String> = matches.iter().map(|x| x.to_string()).collect();
            println!(
                "{{\"tool\":\"tagscan\",\"variant\":\"{s}\",\"phase\":\"receiver_scan\",\"n\":{n},\"threads\":{threads},\"wall_s\":{wall:.6},\"cpu_s\":{:.6},\"us_per_entry_cpu\":{:.3},\"load_s\":{load_s:.6},\"maxrss_kb\":{},\"download_bytes\":{},\"matches\":[{}]}}",
                u1.cpu_s - u0.cpu_s,
                (u1.cpu_s - u0.cpu_s) / n as f64 * 1e6,
                u1.maxrss_kb,
                board.len(),
                m.join(",")
            );
        }
        _ => {
            eprintln!("usage: tagscan keygen|build-board|scan [--scheme S] --key value ...");
            std::process::exit(2);
        }
    }
}
