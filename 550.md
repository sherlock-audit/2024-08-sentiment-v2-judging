Merry Butter Dog

Medium

# Crutial operations like borrowing/repaying will not work on Polygon

## Summary

In contest's README it's stated that the contracts will be deployed on: "Any EVM-compatbile network". However the protocol will not work on every EVM-compatible chain. More specifically all the chains which don't have the sequencer upfeed or available price feeds, in the project's context - Polygon

The protocol uses 3 kind of oracles, Chainlink, RedStone and a custom made fixed price oracle. However an issue can occur when retrieving the prices of assets, when the contracts are deployed on Polygon. Explained more detailly in the below section.

## Vulnerability Detail

When users try to borrow or repay assets, constantly the `_getValueOf` function is called to retrieve the needed prices from a particular oracle set by the RiskEngine: 

```javascript
function _getValueOf(address asset, uint256 amt) internal view returns (uint256) {
        address oracle = RiskEngine(riskEngine).getOracleFor(asset);
        return IOracle(oracle).getValueInEth(asset, amt);
    }
```

However there are few considerations not taken of concern: 

1. On the Chainlink oracles, a check is made to ensure some L2 chains sequencer is up: 

```javascript
function _checkSequencerFeed() private view {
        (, int256 answer, uint256 startedAt,,) = ARB_SEQ_FEED.latestRoundData();

        // answer == 0 -> sequncer up
        // answer == 1 -> sequencer down
        if (answer != 0) revert ChainlinkEthOracle_SequencerDown();
        if (startedAt == 0) revert ChainlinkEthOracle_InvalidRound();

        if (block.timestamp - startedAt <= SEQ_GRACE_PERIOD) revert ChainlinkEthOracle_GracePeriodNotOver();
    }
```

The problem is that, this function is revoked everytime when `getValueInEth()` is called: 

```javascript
function getValueInEth(address asset, uint256 amt) external view returns (uint256) {
        _checkSequencerFeed();

        // [ROUND] price is rounded down. this is used for both debt and asset math, neutral effect.
        return amt.mulDiv(_getPriceWithSanityChecks(asset), (10 ** IERC20Metadata(asset).decimals()));
    }
```

But the sequencer uptime feed is not available on Polygon per Chainlink [docs](https://docs.chain.link/data-feeds/l2-sequencer-feeds#available-networks), and since the uptime feed address is set in the constructor, means it can't be changed: 

```javascript
 constructor(address owner, address arbSeqFeed) Ownable() {
        ARB_SEQ_FEED = IAggegregatorV3(arbSeqFeed);
```

The prices can't be retrieved and the users can't interact with the borrow/repay functions, which beats the purpose of the protocol.

2. On the RedStone oracle, as per their [docs](https://docs.redstone.finance/docs/get-started/price-feeds#available-on-chain-classic-model), currently there are not available price feeds for Polygon chain, so the impact will be the same as above.

## Impact

1. If Chainlink oracles are set in Polygon: even if the sequencer feed is set to an address from the supported networks in the constructor, if the sequencer goes down on the available chain, that means users can't retrieve prices on Polygon also, which is not an option
2. Even if the RedStone oracle is set for Polygon: since there are not available feeds, implementing the fixed price oracle as default one for Polygon is also not an option since the price there is also `immutable`, but the prices of the assets are esentially fluctuating

- Impact: High, as described above oracles functionality will be completely bricked on Polygon, thus bricking the borrow/repay functions also
- Likelihood: Low, as it requires a deployment to Polygon L2
- Overall: Medium

## Code Snippet

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/oracle/ChainlinkEthOracle.sol#L58-L59
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/oracle/ChainlinkEthOracle.sol#L67-L68

## Tool used

Manual Review

## Recommendation

The oracle logic will function properly on the Chainlink oracles, if there is no check for the sequencer. So i would suggest to implement a function which is retrieving the chain id:

```javascript
uint256 public chainid;

function()... {
    assembly {
        chainid := chainid()
}
```

Upon revoking the `getValueInEth()` function first check if the chain id is the same as Polygon's, if there is a match skip the sequencer feed check, in order to prevent the reverts