use clap::{Parser, Subcommand};
use ethers::types::{Address, Bytes, U256};
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{self, Read};
use std::process::Command;
use std::str::FromStr;
use submitter::submitter::{check_bug_impl, Submitter};
use submitter::tx_validation::{validate_transaction, TxSpec};

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
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn gen_attestation() -> Result<String, Box<dyn Error>> {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/gen_attestation.py");
    let output = Command::new("python3").arg(script).output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("gen_attestation.py failed: {stderr}").into());
    }

    let output = String::from_utf8(output.stdout)?;
    Ok(output.trim_end().to_string())
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// [Default Mode] Run bug check and submission using local Foundry files.
    Foundry,
    /// [Validation Mode] Run validation logic with specified on-chain parameters.
    Validation(ValidationArgs),
}

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
    pub value: Option<String>,

    #[arg(long, help = "The transaction data (hex-encoded)")]
    pub data: String,

    #[arg(long, help = "The gas limit for the transaction")]
    pub gas_limit: Option<u64>,

    #[arg(long, help = "The gas price for the transaction")]
    pub gas_price: Option<u64>,
}

fn submit_bug(bug: &[u8]) -> Result<(), Box<dyn Error>> {
    let submitter = Submitter::new();

    // The compatibility backend shares atomically-created, ignored local key
    // files with the legacy receiver. No matching private key is committed.
    let (_enc_secret, enc_pk) = utils::pke::key_gen();
    let params = rust_omr::setup::gen_param(128, 0.1, 0.1);
    let (_omr_secret, omr_public) = rust_omr::setup::keygen(&params);

    let (omr_item, db_entry) = submitter.submit_bug(&enc_pk, &omr_public.pk_clue, bug);
    println!("Bug submitted successfully");
    let attestation = Some(gen_attestation()?);
    let data_to_submit = utils::db::data_to_submitted_data(omr_item, db_entry, attestation);
    let json_file_path = "../../submitted_data.json";
    utils::db::write_data_to_json_file(&data_to_submit, json_file_path)
        .map_err(|error| format!("failed to write {json_file_path}: {error}"))?;
    Ok(())
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
    let check = check_bug_impl(&contract_addr, block_num, &bug_file, &test_file);

    assert!(check, "Bug check failed");

    let mut bug_file = File::open(bug_file)?;
    let mut buffer = Vec::new();
    bug_file.read_to_end(&mut buffer)?;
    submit_bug(&buffer)
}

async fn run_validation_mode(args: &ValidationArgs) -> Result<(), Box<dyn Error>> {
    let from = Address::from_str(&args.from)?;
    let to = Address::from_str(&args.to)?;
    let value = U256::from_dec_str(args.value.as_deref().unwrap_or("0"))?;
    let data_bytes = args.data.strip_prefix("0x").unwrap_or(&args.data);
    let data = Bytes::from(hex::decode(data_bytes)?);

    let tx_spec = TxSpec {
        from,
        to,
        value,
        data: data.clone(),
        gas_limit: args.gas_limit.unwrap_or(1_000_000),
        gas_price: U256::from(args.gas_price.unwrap_or(1_000_000_000_u64)),
        fund_eth: 0.01,
    };

    let addresses = vec![to];
    let tokens = vec![
        Address::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")?,
        Address::from_str("0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599")?,
        Address::from_str("0x6b175474e89094c44da98b954eedeac495271d0f")?,
        Address::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")?,
        Address::from_str("0xdac17f958d2ee523a2206206994597c13d831ec7")?,
    ];

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
        submit_bug(data.as_ref())?;
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let command = cli.command.unwrap_or(Commands::Foundry);

    match command {
        Commands::Foundry => run_foundry_mode(),
        Commands::Validation(args) => run_validation_mode(&args).await,
    }
}
