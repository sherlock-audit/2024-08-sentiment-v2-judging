Sharp Sapphire Ferret

Medium

# Users can still withdraw some of their tokens after a full liquidation

## Summary
Positions may earn rewards from Pendle or GMX, however with enough different tokens and few available oracles these rewards may not be listed inside the position, meaning on liquidation the liquidator will not take these assets away, allowing the lender to just pick them up after the liquidation.

## Vulnerability Detail
Positions would be able to interact with Pendle, GMX and possibly other protocols. However the issue faced here is that these protocols may distribute rewards and in the case with Pendle will split the main token into 2. These tokens will have value, but will lack any kind of oracle to verify their price, meaning that they won't be listed as assets.

The example with Pendle is really good, as [one if the allowed assets](https://gist.github.com/ruvaag/58c9fc2e5c139451c83c21fda27b77a2) would be `PT Ethena USDe` however that asset lacks an oracle to verify it's price, thus it would be "invisible" inside the vault.

This means that after a full liquidation the users can still access his position and withdraw those tokens.

## Impact
Even in cases of bad debt, unlisted assets will not be liquidated. They will put a strain on the system and push it closer to more liquidations and bad debt in fast markets.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L469-L473
```solidity
        for (uint256 i; i < assetDataLength; ++i) {
            if (Position(payable(position)).hasAsset(assetData[i].asset) == false) {
                revert PositionManager_SeizeInvalidAsset(position, assetData[i].asset);
            }
```
## Tool used
Manual Review

## Recommendation
If oracles do not exist for those assets, consider giving them to the liquidators as profit, or put them on an auction giving the profits to the system in case of bad debt.
