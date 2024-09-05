Acrobatic Myrtle Goblin

Medium

# Missing minimum acceptable amounts

## Summary
The `ERC4626` standard was implemented by a vault system presented in the [SuperPool.sol](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L25)
## Vulnerability Detail
As stated in `EIP-4626`:
 * If implementors intend to support EOA account access directly, they should consider
adding an additional function call for `deposit/mint/withdraw/redeem` with the means to
accommodate slippage loss or unexpected `deposit/withdrawal` limits, since they have no
other means to revert the transaction if the exact output amount is not achieved.

## Impact
As the vault is intended to be used directly by `EOA` accounts, the lack of minimum acceptable amount
controls can result in significant `slippage`. This `slippage` can cause users to receive fewer tokens or
shares than anticipated due to variations in the exchange rate that may occur before the actual
transaction execution.

## Code Snippet

## Tool used

Manual Review

## Recommendation

Consider adding parameters to both the `deposit`, `withdraw`, `mint` and `redeem` functions allowing users to
specify minimum acceptable amounts for their transactions and ensure these amounts are checked and
enforced.
