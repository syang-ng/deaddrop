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
    block_time: Option<u64>,
) -> Result<(AnvilInstance, Provider<Http>, u64)> {

    let mut anvil = Anvil::new().fork(upstream);
    if let Some(block_num) = fork_block {
        anvil = anvil.fork_block_number(block_num);
    }
    if let Some(bt) = block_time {
        anvil = anvil.block_time(bt);
    }

    let anvil_instance = anvil.spawn();

    let provider = Provider::<Http>::try_from(anvil_instance.endpoint())?.interval(Duration::from_millis(50));

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

pub async fn validate_transaction(
    tx: &TxSpec,
    upstream: &str,
    fork_block: Option<u64>,
    block_time: Option<u64>,
    addresses: &[Address],
    tokens: &[Address],
) -> Result<bool> {
    let (anvil_instance, provider, chain_id) = setup_fork(upstream, fork_block, block_time)?;
    let faucet_wallet = LocalWallet::from(anvil_instance.keys()[0].clone()).with_chain_id(chain_id);
    let client = SignerMiddleware::new(provider.clone(), faucet_wallet);

    let pre = sum_balances_per_token(&provider, addresses, tokens).await?;

    let _ok: bool = provider.request("anvil_impersonateAccount", [tx.from]).await?;
    if tx.fund_eth > 0.0 {
        client
            .send_transaction(TransactionRequest::pay(tx.from, parse_ether(tx.fund_eth)?), None)
            .await?
            .await?
            .ok_or_else(|| anyhow!("funding tx failed"))?;
    }

    // estimate gas price
    let base_fee: U256 = provider.request("eth_gasPrice", ()).await?;
    let gas_price = if tx.gas_price < base_fee {
        base_fee
    } else {
        tx.gas_price
    };

    // send transaction
    let req = TransactionRequest::new()
        .from(tx.from)
        .to(tx.to)
        .value(tx.value)
        .data(tx.data.clone())
        .gas(tx.gas_limit)
        .gas_price(gas_price);
    let tx_hash: H256 = client.provider().request("eth_sendTransaction", [req]).await?;
    let pending = PendingTransaction::new(tx_hash, client.provider());
    let receipt = pending
        .await?
        .ok_or_else(|| anyhow!("no receipt (tx not mined)"))?;

    if receipt.status != Some(1u64.into()) {
        return Err(anyhow!("tx failed or reverted: {:?}", receipt));
    }
    
    let post = sum_balances_per_token(&provider, addresses, tokens).await?;
    for token in tokens {
        let a = pre.get(token).cloned().unwrap_or_default();
        let b = post.get(token).cloned().unwrap_or_default();
        if a < b {
            println!("❌ Token {:?} changed: before = {}, after = {}", token, a, b);
            return Ok(false);
        }
    }
    println!("✅ All token balances unchanged");
    Ok(true)
}