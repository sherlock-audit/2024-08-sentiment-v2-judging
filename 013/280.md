Attractive Caramel Fox

Medium

# PUSH0 opcode not available on Fantom and Linea

## Summary
PUSH0 opcode not available on Fantom and Linea

## Vulnerability Detail
As mentioned in the contest README, the protocol will be deployed on every EVM-compatible chain. Fantom is a fully compatible EVM network (https://docs.fantom.foundation/technology/faq):
>Is Fantom compatible with Ethereum smart contracts?
Yes. Fantom is fully compatible with the Ethereum Virtual Machine (EVM) and supports Web3JS API and RPC.

The PUSH0 opcode was introduced in 0.8.20 and is available on the Shanghai EVM version. As seen in the `foundry.toml`, here are the Solidity and EVM version used:
>solc_version = '0.8.24'
evm_version = 'shanghai'

The PUSH0 opcode however is not available on Fantom. To test that out, run the following command (replace `{FANTOM_RPC_URL}` with a Fantom RPC URL):
`cast call --block 89249810 --rpc-url {FANTOM_RPC_URL} --create 0x5f`

The block number used is one of the latest ones as of the time of writing this report. The command will return the following error:
`server returned an error response: error code -32000: invalid opcode: opcode 0x5f not defined`

`0x5f` is the PUSH0 opcode (https://eips.ethereum.org/EIPS/eip-3855). If you try this command on a different network with PUSH0 available on it and the according block number, it will be successful.

It also is not available on Linea: https://docs.linea.build/developers/quickstart/ethereum-differences#evm-opcodes

## Impact
PUSH0 opcode not available on Fantom and Linea

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/Pool.sol#L25
## Tool used

Manual Review

## Recommendation
Use a lower version or do not deploy on chains with no PUSH0 support