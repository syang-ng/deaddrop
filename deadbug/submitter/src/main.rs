use clap::{Parser, Subcommand};
use ethers::types::{Address, Bytes, U256};
use hex;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{self, Read};
use std::process::Command;
use std::str::FromStr;
use submitter::submitter::{check_bug_impl, Submitter};
use submitter::tx_validation::{validate_transaction, TxSpec};
use utils::pke::pk_from_string;

// use crate::check_bug_impl; // Uncomment and fix this if check_bug_impl exists elsewhere
fn read_contract_addr(file_path: &str) -> io::Result<String> {
    let mut file = File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents.trim().to_string())
}

fn read_block_num(file_path: &str) -> io::Result<u32> {
    let mut file = File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    contents
        .trim()
        .parse::<u32>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn gen_attestation() -> Result<String, Box<dyn Error>> {
    // Spawn `python3 gen_attestation.py`
    let output = Command::new("python3").arg("gen_attestation.py").output()?; // waits for the script to finish

    // Check the exit code
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("gen_attestation.py failed: {}", stderr).into());
    }

    // Parse stdout as UTF-8, trim trailing newline, and return
    let s = String::from_utf8(output.stdout)?;
    Ok(s.trim_end().to_string())
}

/// The main command-line interface structure for the application.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

/// Defines the available subcommands.
#[derive(Subcommand, Debug)]
enum Commands {
    /// [Default Mode] Run bug check and submission using local Foundry files.
    Foundry,
    /// [Validation Mode] Run validation logic with specified on-chain parameters.
    Validation(ValidationArgs),
}

/// Arguments required for the `validation` subcommand.
#[derive(Parser, Debug)]
pub struct ValidationArgs {
    #[arg(long, help = "URL of the RPC service")]
    pub rpc_url: String,

    #[arg(long, help = "The block number to validate against")]
    pub block_number: u64,

    #[arg(long, help = "The timestamp of the block")]
    pub block_time: u64,

    #[arg(long, help = "The sender address of the transaction")]
    pub from: String,

    #[arg(long, help = "The recipient address of the transaction")]
    pub to: String,

    #[arg(long, help = "The value of the transaction (in wei)")]
    pub value: Option<String>, // Using String to support large numbers (U256)

    #[arg(long, help = "The transaction data (hex-encoded)")]
    pub data: String,

    #[arg(long, help = "The gas limit for the transaction")]
    pub gas_limit: Option<u64>,

    #[arg(long, help = "The gas price for the transaction")]
    pub gas_price: Option<u64>,
}

fn submit_bug(bug: &[u8]) {
    let submitter = Submitter::new();

    // let enc_pk_file = "test/enc_pk.txt";
    // let enc_pk = File::open(enc_pk_file).expect("Failed to open enc_pk file");
    let enc_pk_str = "age10x4whtpda5dqcmty2m4pza02e6y9lxx8zqz7duelrjkmxmvn8emsnc2ydd";
    let enc_pk = pk_from_string(enc_pk_str);
    let clue_key_str = "1c0fda1929df4033c3caf80ce1504cc7e9349f9c56661d57eaabf36c29d7c54e";
    let clue_key = hex::decode(clue_key_str).expect("Failed to decode clue key from hex");
    // let clue_key_file = "test/clue_key.txt";
    // let clue_key = File::open(clue_key_file).expect("Failed to open clue_key file");

    let (omr_item, db_entry) = submitter.submit_bug(&enc_pk, &clue_key, bug);
    println!("Bug submitted successfully");
    let attestation = Some(gen_attestation().unwrap());
    let data_to_submit = utils::db::data_to_submitted_data(omr_item, db_entry, attestation);
    let json_file_path = "../../submitted_data.json";
    utils::db::write_data_to_json_file(&data_to_submit, json_file_path)
        .expect("Failed to write data to JSON file");
}

fn run_foundry_mode() -> Result<(), Box<dyn Error>> {
    let bug_file = env::var("BUG_FILE").expect("Environment variable BUG_FILE is not set");
    let block_num_file =
        env::var("BLOCK_NUM_FILE").expect("Environment variable BLOCK_NUM_FILE is not set");
    let test_file = env::var("TEST_FILE").expect("Environment variable TEST_FILE is not set");
    let contract_addr_file =
        env::var("CONTRACT_ADDR_FILE").expect("Environment variable CONTRACT_ADDR_FILE is not set");

    let block_num = read_block_num(&block_num_file)?;
    let contract_addr = read_contract_addr(&contract_addr_file)?;
    // // Check the correctness of the bug
    let check = check_bug_impl(&contract_addr, block_num, &bug_file, &test_file);

    assert!(check, "Bug check failed");

    // Now read the bug file, encryption stuff and submit the bug

    let mut bug_file = File::open(bug_file)?;
    let mut buffer = Vec::new();
    bug_file.read_to_end(&mut buffer)?;
    let bug = buffer.as_slice();

    submit_bug(bug);
    Ok(())
}

async fn run_validation_mode(args: &ValidationArgs) -> Result<(), Box<dyn Error>> {
    let from = Address::from_str(&args.from)?;
    let to = Address::from_str(&args.to)?;
    let value = U256::from_dec_str(&args.value.as_deref().unwrap_or("0"))?;
    let data_bytes = if args.data.starts_with("0x") {
        &args.data[2..]
    } else {
        &args.data
    };

    let data = Bytes::from(hex::decode(data_bytes)?);

    let tx_spec = TxSpec {
        from,
        to,
        value,
        data: data.clone(),
        gas_limit: args.gas_limit.unwrap_or(1_000_000), // Default to 1M
        gas_price: U256::from(args.gas_price.unwrap_or(1_000_000_000u64)), // Default to 1 Gwei
        fund_eth: 0.01,                                 // Fund with 0.01 ETH for gas
    };

    // Define addresses and tokens to monitor
    let addresses = vec![to];
    let tokens = vec![
        Address::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")?, // WETH
        Address::from_str("0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599")?, // WBTC
        Address::from_str("0x6b175474e89094c44da98b954eedeac495271d0f")?, // DAI
        Address::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")?, // USDC
        Address::from_str("0xdac17f958d2ee523a2206206994597c13d831ec7")?, // USDT
    ]; // Add token addresses if needed

    let same = validate_transaction(
        &tx_spec,
        &args.rpc_url,
        Some(args.block_number),
        Some(args.block_time),
        &addresses,
        &tokens,
    )
    .await?;

    if same {
        println!("❌ Transaction does not violate invariants.");
    } else {
        submit_bug(data.as_ref());
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    // If no subcommand is provided, default to Foundry mode.
    let command = cli.command.unwrap_or(Commands::Foundry);

    match command {
        Commands::Foundry => run_foundry_mode(),
        Commands::Validation(args) => run_validation_mode(&args).await,
    }
}
