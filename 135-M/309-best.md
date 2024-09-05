Mammoth Rosewood Okapi

High

# The liquidate() function requires that after liquidation, the position must be in a healthy state. This may result in certain positions never being liquidated if they cannot reach a healthy state, potentially leaving them in limbo.


## Summary
Since the position’s funds are discounted during liquidation, this could further deteriorate the position’s health instead of restoring it. As a result, the lender’s funds could be exposed to even greater risk, rather than mitigating the situation as intended.
## Vulnerability Detail
```javascript
    function liquidate(
        address position,
        DebtData[] calldata debtData,
        AssetData[] calldata assetData
    ) external nonReentrant {
        riskEngine.validateLiquidation(position, debtData, assetData);

        // liquidate
        _transferAssetsToLiquidator(position, assetData);
        _repayPositionDebt(position, debtData);

        // position should be within risk thresholds after liquidation
@>>        if (!riskEngine.isPositionHealthy(position)) revert PositionManager_HealthCheckFailed(position);
        emit Liquidation(position, msg.sender, ownerOf[position]);
    }
```
We can see that the liquidate() function requires the position to be in a healthy state after liquidation. Although liquidators are given the opportunity to acquire collateral at a discounted price (e.g., 10%), because the position must be restored to a healthy state after liquidation, the liquidator’s profit in some cases may be very small or even nonexistent. This lack of incentive for the liquidator could result in certain positions remaining unliquidated, leading to further losses for the lender.

Proof of Concept (POC):

Let’s take an example scenario:

Assume an asset has an LTV of 98%, a price of 1, and a quantity of 100.

The borrow token quantity is 98, with a price of 1, and the borrowed amount is 98.

The loan value is 98, and the minimum collateral value is 100.

The position is currently in a healthy state.


When the price drops by 1.5%, i.e., the price becomes 0.985, the collateral value is 98.5, which is less than 100.

At this point, the position becomes eligible for liquidation.

The liquidator’s profit from liquidating the entire position would be 1. However, the discounted price is calculated as   1-98.5/99 = 0.5% , which results in a 0.5% discount—far below the expected 10%. This might not be sufficient to motivate the liquidator to liquidate the position.

As a result, if the price drops further, the liquidator’s profit decreases even more. In the volatile world of cryptocurrencies, a 20%-30% price drop is common during market crashes, which could lead to a large number of positions becoming unliquidatable.

If the liquidator liquidates a portion of the position at a discounted price (10%), it would actually make the position even more unhealthy, causing the transaction to revert.

For example, if the liquidator tries to liquidate 10 borrow tokens, they would need to acquire collateral equivalent to:


10*1/（0.985 *（1-10%）） = 11.28


The remaining position would be:

	•	Borrow tokens: 88
	•	Required collateral: 89.7959
	•	Remaining collateral: 88.71968
	•	Value of remaining collateral: 87.3888

As we can see, the health of the position decreases further rather than restoring it to a healthy state. This worsens the situation and prevents the position from being brought back to a healthy state, leading to a revert.

Therefore, this creates a situation where the position becomes unliquidatable.


## Impact
Some positions cannot be liquidated, resulting in losses for the lender.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L430
## Tool used

Manual Review

## Recommendation
The liquidation process should be allowed as long as it does not worsen the health of the position, even if it doesn’t fully restore the position to a healthy state. This would help minimize losses for the lender.