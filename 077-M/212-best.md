Expert Nylon Leopard

Medium

# Ideally Liquidation should revert when the position becomes a Bad Debt but it doesn't, hence the Lack of Slippage Protection in Liquidation Process Exposes Liquidators to Losses when there is Network Congestion and high Market Volatility

## Summary

The liquidation process in the protocol is intended to revert once a position enters bad debt. However, during periods of high network congestion and market volatility, the current implementation fails to protect liquidators from incurring losses. The delay between the execution of a liquidation transaction and its actual processing can result in a position turning into bad debt. This exposes liquidators to significant financial risks, especially when they are frontrun by attackers or when the network is congested.

## Vulnerability Detail

In situations of high network congestion or rapid market movements, a liquidation transaction that was valid at the time of initiation might become invalid by the time it is processed. For instance, on a congested Ethereum network, the transaction might be delayed, and during this delay, the price of the collateral could drop significantly, pushing the position into bad debt.

Since the protocol currently does not have a mechanism to check and revert the liquidation process if the position becomes a bad debt during the delay, liquidators can end up losing funds. 

**Also**, This issue is exacerbated by the possibility of front-running attacks, where an attacker deliberately manipulates the market to turn a healthy position into a bad debt after a liquidation call has been made but before it is executed.

## Impact


The lack of a slippage protection mechanism in the liquidation process can lead to substantial losses for liquidators. In highly volatile and congested environments, the liquidator's funds are at risk, making the liquidation process unprofitable and potentially driving away participants from engaging in liquidations. 

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L426-L444

## Tool used

Manual Review

## Recommendation

To mitigate this issue, it is recommended to implement a slippage protection check within the liquidation process. This check should ensure that the position's health is reassessed right before the liquidation is finalized. If the position has turned into bad debt during the delay, the liquidation should be reverted to protect the liquidator.

### Suggested Implementation:

1. **Pre-Liquidation Health Check:** Add a final check to ensure the position is still healthy just before the liquidation is executed, that is toatl asset value is still greater than the debt value.
  
2. **Slippage Tolerance:** Introduce a slippage tolerance mechanism to ensure that the value of the collateral does not fall below a certain threshold during the transaction processing time.

3. **Revert on Bad Debt:** If the position is found to be in bad debt during the final check, revert the transaction to prevent the liquidator from incurring losses.