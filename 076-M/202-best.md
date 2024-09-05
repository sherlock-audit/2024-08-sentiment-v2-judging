Keen Jetblack Turtle

Medium

# Fee Change Race Conditions Expose Users to Unexpected Losses

## Summary
- The `PositionManager` and Pool contracts lack slippage protection for borrowers and liquidators, exposing them to potential losses due to fee changes between transaction submission and execution.
## Vulnerability Detail

- The vulnerability stems from potential race conditions in the borrowing and liquidation processes, where fee changes can occur between transaction initiation and execution.

1. Borrowing:
- In the PositionManager's `borrow` function and Pool's `borrow` function, users request to borrow a specific amount of assets. However, the actual amount received can be unexpectedly reduced if the pool's origination fee is changed before the transaction is processed.
```js
function borrow(uint256 poolId, address position, uint256 amt) external returns (uint256 borrowShares) {
    // ... (code omitted for brevity)
    uint256 fee = amt.mulDiv(pool.originationFee, 1e18);
    // ... (remaining code)
}

```
The `originationFee` can be changed by the pool owner at any time.
```js 
function setOriginationFee(uint256 poolId, uint128 originationFee) external onlyOwner {
    if (originationFee > 1e18) revert Pool_FeeTooHigh();
    poolDataFor[poolId].originationFee = originationFee;
    emit OriginationFeeSet(poolId, originationFee);
}
```
2. Liquidation:
Similarly, in the PositionManager's `liquidate` function, liquidators may receive fewer assets than expected if the liquidation fee is changed before their transaction is processed.
```js
function _transferAssetsToLiquidator(address position, AssetData[] calldata assetData) internal {
    // ... (code omitted for brevity)
    uint256 fee = liquidationFee.mulDiv(assetData[i].amt, 1e18);
    // ... (remaining code)
}
```
The `liquidationFee` can be adjusted by the Pool owner at any time.
```js
function setLiquidationFee(uint256 _liquidationFee) external onlyOwner {
    liquidationFee = _liquidationFee;
    emit LiquidationFeeSet(_liquidationFee);
}
```
- In both scenarios, users (borrowers or liquidators) have no control over the minimum amount of assets they receive. A change in fees between transaction submission and execution can result in significantly different outcomes than expected, leading to unfavorable positions or unprofitable liquidations.

- It's important to note that this vulnerability doesn't require malicious intent from the owner. Regular fee adjustments, even if well-intentioned, can inadvertently cause these issues due to the lack of slippage protection for users.

The flaw can be demonstrated as follows (e.g `originationFee`):

1. A user submits a loan request expecting to borrow $1000 with an origination fee of 1%.
2. Concurrently, the pool owner initiates a transaction that updates the origination fee to 10%.
3. If the pool owner’s transaction gets confirmed before the user’s transaction, the user will receive only $900 instead of the expected $990.


## Impact

- Borrowers may receive fewer assets than expected, disrupting their financial strategies, this could be significantly harmful if users use high leverage (sentiment allows for up to 20 times leverage, the origination fee loss could be significant)
- Liquidators might execute unprofitable liquidations due to unexpected fee increases.

## Code Snippet
- https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L476
- https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L384
- 
## Tool used

Manual Review


## Recommendation

Implement slippage protection for both borrowing and liquidation processes:

1. For borrowing, add a `minAmountOut` parameter to the `borrow` function
2. For liquidations, add a `minSeizableAmount` parameter to the `liquidate` function:
