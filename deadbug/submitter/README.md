## Bug Submission

The no-feature compatibility backend creates its AGE and mock-OMR key files
atomically on first use and shares them with the legacy receiver. The generated
mode-`0600` files are ignored by Git. Set `DEADDROP_LEGACY_AGE_KEYS_FILE` and
`DEADDROP_LEGACY_OMR_KEYS_FILE` to explicit shared paths when submitter and
receiver use different working directories.

### Foundry Test

Test the contract with foundry.

Provide an Ethereum mainnet RPC through either environment variable:

```bash
export INFURA_PROJECT_ID="your-project-id"
# Or use any Ethereum RPC provider:
export MAINNET_RPC_URL="https://your-mainnet-rpc.example"
```

### Outside Market Validation

The idea is that the contract owner submits a contract and specifies the properties they aim to achieve, for example, asset security. Then, bug bounty hunters from an open market can use their own methods to find vulnerabilities that break these properties. In this system, we receive an exploit transaction from a bug bounty hunter and execute it. If the property is violated after the transaction's execution, we confirm that they have indeed found a bug.

In the example below, the bug bounty hunter submits an exploit transaction to transfer 1 wei of WETH from the target contract, which violates the asset security property.


```bash
./build/release/submitter validation --rpc-url http://127.0.0.1:8545 --block-number 23555153 --block-time 1760193791 --from 0x9696f59E4d72E237BE84fFD425DCaD154Bf96976 --to 0x64F2095CC11e4726078F4A64d4279c7e7fB7e6Ec --value 0 --data 0xfa461e330000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000020000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2
```
