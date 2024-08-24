Abundant Maroon Pangolin

Medium

# Missing 'minDebt' check from liquidation can lead to bad debt accumulation

### Summary


The missing `minDebt` check from `PositionManager.liquidate` can leave positions with a small amount of debt that is unappealing to further liquidations and  can lead to accumulation of bad debt. 

### Root Cause

Protocol implements a `borrowAssets < minDebt` check in `Pool.borrow` ([link](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L452)) and `Pool.repay` ([link2](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L511)), but this check is missing from liquidations. 

### Internal pre-conditions

1. An unhealthy position must exist.

### External pre-conditions

none

### Attack Path

1. An liquidator/attacker observes an unhealthy positions and calls `PositionManager.liquidate` and repays just enough debt such that after liquidations  `0 < the new position's debt < minDebt`. 
2. After 1st liquidation position became sound with debt < assets deposited.
3. After some time, due to market conditions, same position became unhealthy again. But due to gas prices and small position the liquidators are disincentivized to liquidate it.  
4. Due to further asset's prices decrease, position accumulate bad debt and lenders must take a loss. 
Since the protocol can be deployed to Ethereum L1 small

### Impact

Protocol can have many positions with `debt < minDebt`. Over time, since there will be no incentive for liquidators to liquidate small underwater positions given the gas cost, protocol accumulates bad debt at the detrimental of lenders.

### PoC

_No response_

### Mitigation

Ensure that liquidators liquidate entire position's debt or, that the remaining debt after liquidation is bigger than `minDebt`. 