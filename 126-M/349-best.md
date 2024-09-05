Huge Honeysuckle Rabbit

Medium

# Borrowers can self liquidate themselves without losing bad debt amount.

## Summary
The borrowers can self liquidate themselves without the collateral being seized.

## Vulnerability Detail
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L430-L444

Suppose There is an user Alice, She borrowed $600 worth of tokenA which has LTV of 70%, by putting $1000 worth tokenB as collateral. 

Now if the price of collateral drops and the ltv has crossed 70%, lets say collateral worth now $750. the position is liquidatable now, and liquidator should liquidate this position by repaying the bad debt and seized the borrower collateral. 
But borrower can liquidate his position and the collateral will not be seized.


## Impact
Medium, Borrower does not loose his collateral even after if the position is unhealty and have the incentives to open bad debt position.

## Code Snippet
```solidity
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
        if (!riskEngine.isPositionHealthy(position)) revert PositionManager_HealthCheckFailed(position);
        emit Liquidation(position, msg.sender, ownerOf[position]);
    }
```

## Tool used

Manual Review

## Recommendation
Add a check that borrower position owner can't liquidate his position.
```diff
    function liquidate(
        address position,
        DebtData[] calldata debtData,
        AssetData[] calldata assetData
    ) external nonReentrant {
+ if (ownerOf[position] == msg.sender) revert PositionManager_SelfLiquidation();
// @info as position owner can give authority to another address
 + if (isAuth[position][msg.sender]) revert PositionManger_AuthorityLiquidation(); 
        riskEngine.validateLiquidation(position, debtData, assetData);

        // liquidate
        _transferAssetsToLiquidator(position, assetData);
        _repayPositionDebt(position, debtData);

        // position should be within risk thresholds after liquidation
        if (!riskEngine.isPositionHealthy(position)) revert PositionManager_HealthCheckFailed(position);
        emit Liquidation(position, msg.sender, ownerOf[position]);
    }
```