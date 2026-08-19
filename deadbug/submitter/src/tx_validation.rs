use anyhow::{anyhow, Result};
use ethers::prelude::*;
use ethers::utils::{Anvil, AnvilInstance};
use std::collections::BTreeMap;
use std::time::Duration;


#[derive(Clone, Debug)]
pub struct TxSpec {
    pub from: Address,
    pub to: Address,
    pub value: U256,
    pub data: Bytes,
    pub gas_limit: u64,
    pub gas_price: U256,
    // funding the from address
    pub fund_eth: f64,
}


pub fn setup_fork(
    upstream: &str,
    fork_block: Option<u64>,
) -> Result<(AnvilInstance, Provider<Http>, u64)> {

    let mut anvil = Anvil::new().fork(upstream);
    if let Some(block_num) = fork_block {
        anvil = anvil.fork_block_number(block_num);
    }
    anvil = anvil.port(28545u16);

    let anvil_instance = anvil.spawn();
    println!("🎯 Anvil fork started at: {}", anvil_instance.endpoint());

    let provider = Provider::<Http>::try_from(anvil_instance.endpoint())
        .map_err(|e| anyhow!("Failed to create provider: {}", e))?
        .interval(Duration::from_millis(100));

    let chain_id = anvil_instance.chain_id();

    Ok((anvil_instance, provider, chain_id))
}

abigen!(IERC20, r#"[
    function balanceOf(address) view returns (uint256)
]"#);

fn parse_ether(v: f64) -> Result<U256> {
    let s = format!("{:.0}", v * 1e18);
    Ok(U256::from_dec_str(&s)?)
}

async fn sum_balances_per_token(
    provider: &Provider<Http>,
    addresses: &[Address],
    tokens: &[Address],
) -> Result<BTreeMap<Address, U256>> {
    let mut sums: BTreeMap<Address, U256> = BTreeMap::new();

    for &token in tokens {
        let contract = IERC20::new(token, provider.clone().into());
        let mut total = U256::zero();

        for &addr in addresses {
            let bal = contract.balance_of(addr).call().await.unwrap_or(U256::zero());
            total = total.saturating_add(bal);
        }
        sums.insert(token, total);
    }

    Ok(sums)
}

async fn check_rpc_health(upstream: &str) -> Result<()> {
    let provider = Provider::<Http>::try_from(upstream)
        .map_err(|e| anyhow!("Invalid RPC URL {}: {}", upstream, e))?;
    
    let net_version: String = provider.request("net_version", ())
        .await
        .map_err(|e| anyhow!("RPC network check failed: {}", e))?;
    
    let block_number: U64 = provider.request("eth_blockNumber", ())
        .await
        .map_err(|e| anyhow!("RPC block number check failed: {}", e))?;
    
    println!("✅ RPC connection healthy: network={}, block={}", net_version, block_number);
    Ok(())
}



pub async fn validate_transaction(
    tx: &TxSpec,
    upstream: &str,
    fork_block: Option<u64>,
    block_timestamp: Option<u64>,
    addresses: &[Address],
    tokens: &[Address],
) -> Result<bool> {

    check_rpc_health(upstream).await?;

    let (_anvil_instance, provider, _chain_id) = setup_fork(upstream, fork_block)
        .map_err(|e| anyhow!("Failed to setup fork: {}", e))?;

    let pre = sum_balances_per_token(&provider, addresses, tokens)
        .await
        .map_err(|e| anyhow!("Failed to get pre-transaction balances: {}", e))?;

    let _: () = provider.request("anvil_impersonateAccount", [tx.from])
        .await
        .map_err(|e| anyhow!("Failed to impersonate account {}: {}", tx.from, e))?;

    println!("Finished impersonating {}", tx.from);
    if tx.fund_eth > 0.0 {
        let current_balance = provider
            .get_balance(tx.from, None)
            .await
            .map_err(|e| anyhow!("Failed to get sender balance: {}", e))?;
        let funded_balance = current_balance.saturating_add(parse_ether(tx.fund_eth)?);
        let _: () = provider
            .request("anvil_setBalance", (tx.from, funded_balance))
            .await
            .map_err(|e| anyhow!("Failed to fund sender account: {}", e))?;

        println!("Funded sender {} without mining a block", tx.from);
    }

    if let Some(timestamp) = block_timestamp {
        let _: () = provider.request("evm_setNextBlockTimestamp", [timestamp])
            .await
            .map_err(|e| anyhow!("Failed to set next block timestamp: {}", e))?;
    }

    let base_fee: U256 = provider.request("eth_gasPrice", ())
        .await
        .map_err(|e| anyhow!("Failed to get gas price: {}", e))?;
    
    let gas_price = if tx.gas_price < base_fee {
        base_fee
    } else {
        tx.gas_price
    };

    let req = TransactionRequest::new()
        .from(tx.from)
        .to(tx.to)
        .value(tx.value)
        .data(tx.data.clone())
        .gas(tx.gas_limit)
        .gas_price(gas_price);
        
    let tx_hash: H256 = provider.request("eth_sendTransaction", [req])
        .await
        .map_err(|e| anyhow!("Failed to send transaction: {}", e))?;
    
    let pending = PendingTransaction::new(tx_hash, &provider);
    let receipt = pending
        .await
        .map_err(|e| anyhow!("Transaction pending failed: {}", e))?
        .ok_or_else(|| anyhow!("No receipt - transaction not mined"))?;

    if receipt.status != Some(1u64.into()) {
        return Err(anyhow!("Transaction failed or reverted: {:?}", receipt));
    }
    
    let post = sum_balances_per_token(&provider, addresses, tokens)
        .await
        .map_err(|e| anyhow!("Failed to get post-transaction balances: {}", e))?;
    
    for token in tokens {
        let a = pre.get(token).cloned().unwrap_or_default();
        let b = post.get(token).cloned().unwrap_or_default();
        if a > b {
            println!("❌ Token {:?} changed: before = {}, after = {}", token, a, b);
            return Ok(false);
        }
    }
    
    println!("✅ All token balances unchanged");
    Ok(true)
}
