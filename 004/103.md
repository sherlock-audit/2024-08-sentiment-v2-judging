Rapid Bronze Troll

High

# Improper handling of price normalization to `e18` in `RedstoneOracle.sol#getValueInEth`

### Summary

The RedstoneOracle#getValueInEth returns price of `ASSSETe18` mutiplied by `(ASSET/USD) / (ETH/USD)`which are gotten from Redstone Oracles and not scaled to 18 decimals as the `ASSET`.

The problem is that Redstone Oracles are 8 decimals by default which can be seen here [Redstone price feeds decimals](https://github.com/redstone-finance/redstone-oracles-monorepo/blob/9d10a48aad7a2ccb5f3f48396d970fd63761dbce/packages/on-chain-relayer/contracts/price-feeds/PriceFeedBase.sol#L51-L53)

### Root Cause

The issue itself lies in the normalization to `e18` of the returned by the method price.

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/oracle/RedstoneOracle.sol#L67-L71

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

_No response_

### Impact

Financial losses due to inaccuracy in the math.

### PoC

As per openzeppelin math [mulDiv function parameters](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/0b58a783b9b33b63eef2994af8958c0c6a72dc51/contracts/utils/math/Math.sol#L144)
x = amt: Scaled to 18 decimals.
y = assetUsdPrice: 8 decimals.
denominator = ethUsdPrice: 8 decimals.

The calculation performed by the `getValueInEth` function is:
```math

\text{Result} = \frac{\text{amt} \times \text{assetUsdPrice}}{\text{ethUsdPrice}}
```

Substituting the values:
```math
\text{Result} = \frac{(1 \times 10^{18}) \times (1 \times 10^{8})}{2 \times 10^{8}}
```

Simplifying the expression:
```math
\text{Result} = \frac{1 \times 10^{26}}{2 \times 10^{8}} = \frac{1 \times 10^{26}}{2 \times 10^{8}} = 0.5 \times 10^{18} = 5 \times 10^{17}
```
Thus, the function will return:
```math
`\boxed{5 \times 10^{17}}
```

### Mitigation

Consider normalizing the prices of `assetUsdPrice, ethUsdPrice` to `1e18` OR the `asset` price to `1e8` and after that the calculation outcome value to `1e18`

