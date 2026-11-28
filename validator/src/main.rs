use std::error::Error;
#[cfg(feature = "legacy")]
use std::fs::File;
#[cfg(feature = "legacy")]
use std::io::{self, Read};
use std::process::Command;

#[cfg(feature = "legacy")]
fn read_contract_addr(file_path: &str) -> io::Result<String> {
    let mut file = File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents.trim().to_string())
}

#[cfg(feature = "legacy")]
fn read_block_num(file_path: &str) -> io::Result<u32> {
    let mut file = File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    contents
        .trim()
        .parse::<u32>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Run `run_test.sh` script to check whether the given attack violates invariants provided
/// by the bug receiver.
///
/// This function will panic if `run_test.sh` cannot be spawned, or the script exits with code
/// other than 0 or 1.
///
#[cfg(feature = "legacy")]
pub fn check_bug_impl(
    contract_addr: &str,
    block_num: u32,
    bug_filepath: &str,
    inv_filepath: &str,
) -> bool {
    let output = Command::new("./src/run_test.sh")
        .arg(contract_addr)
        .arg(block_num.to_string())
        .arg(bug_filepath)
        .arg(inv_filepath)
        .output()
        .expect("failed to spawn run_test.sh");

    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    match (code, stdout.as_str()) {
        (0, s) if s.eq_ignore_ascii_case("success") => false,
        (1, s) if s.eq_ignore_ascii_case("fail") => {
            // bug violates invariants
            true
        }
        (other, s) => {
            panic!(
                "run_test.sh returned unexpected code {} with stdout={:?} stderr={:?}",
                other, s, stderr
            );
        }
    }
}

#[cfg(feature = "legacy")]
fn validate_legacy() {
    //let bug_file = env::var("BUG_FILE").map_err(|_| "Environment variable BUG_FILE is not set").unwrap();
    //let block_num_file= env::var("BLOCK_NUM_FILE").map_err(|_| "Environment variable BLOCK_NUM_FILE is not set").unwrap();
    //let test_file = env::var("TEST_FILE").map_err(|_| "Environment variable TEST_FILE is not set").unwrap();
    //let contract_addr_file = env::var("CONTRACT_ADDR_FILE").map_err(|_| "Environment variable CONTRACT_ADDR_FILE is not set").unwrap();

    // Get everthing you need for the bug check
    let block_num_file = "data/block.txt";
    let contract_addr_file = "data/addr.txt";
    let bug_file = "data/bug_cond.sol";
    let test_file = "data/bug_report.sol";

    let block_num = read_block_num(&block_num_file).unwrap();
    let contract_addr = read_contract_addr(&contract_addr_file).unwrap();
    // Check the correctness of the bug
    let check = check_bug_impl(&contract_addr, block_num, &bug_file, &test_file);

    assert!(check, "Bug check failed");
}

fn validate_fixture(args: &[String]) -> Result<i32, Box<dyn Error>> {
    let [port, root, solc] = args else {
        return Err("usage: validator --fixture RPC_PORT PROJECT_ROOT SOLC".into());
    };
    let port: u16 = port.parse()?;
    let status = Command::new("forge")
        .args(["test", "--root", root, "--use", solc])
        .args(["--fork-url", &format!("http://127.0.0.1:{port}")])
        .args([
            "--fork-block-number",
            "1",
            "--offline",
            "--no-cache",
            "--no-storage-caching",
        ])
        .args([
            "--match-test",
            "^testPinnedValue\\(\\)$",
            "--threads",
            "1",
            "--json",
        ])
        .status()?;
    status
        .code()
        .ok_or_else(|| "Forge terminated by signal".into())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some((mode, args)) = args.split_first() {
        if mode == "--fixture" {
            std::process::exit(validate_fixture(args)?);
        }
        return Err("unknown validation mode".into());
    }
    #[cfg(feature = "legacy")]
    {
        validate_legacy();
        Ok(())
    }
    #[cfg(not(feature = "legacy"))]
    Err("expected --fixture".into())
}
