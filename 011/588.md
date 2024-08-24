Crazy Sapphire Mandrill

High

# Frontrunning  in `initializePool` Function may leads to DOS and making owner to spend more on pool initialization

## Summary

## Vulnerability Detail
The `initializePool` function in the `Pool.sol` contract is responsible for initializing a new pool with specific parameters. It sets up the pool `owner`, `asset`, `pool cap`, and `interest rate model`, and emits relevant events to signal the initialization.

```solidity
function initializePool(//@audit-frontrunning and setting poolCap very low
        address owner,
        address asset,
        uint128 poolCap,
        bytes32 rateModelKey
    ) external returns (uint256 poolId) {
        if (owner == address(0)) revert Pool_ZeroAddressOwner();

        if (RiskEngine(riskEngine).getOracleFor(asset) == address(0)) revert Pool_OracleNotFound(asset);

        address rateModel = Registry(registry).rateModelFor(rateModelKey);
        if (rateModel == address(0)) revert Pool_RateModelNotFound(rateModelKey);

        poolId = uint256(keccak256(abi.encodePacked(owner, asset, rateModelKey)));
        if (ownerOf[poolId] != address(0)) revert Pool_PoolAlreadyInitialized(poolId);
        ownerOf[poolId] = owner;

        PoolData memory poolData = PoolData({
            isPaused: false,
            asset: asset,
            rateModel: rateModel,
            poolCap: poolCap,
            lastUpdated: uint128(block.timestamp),
            interestFee: defaultInterestFee,
            originationFee: defaultOriginationFee,
            totalBorrowAssets: 0,
            totalBorrowShares: 0,
            totalDepositAssets: 0,
            totalDepositShares: 0
        });

        poolDataFor[poolId] = poolData;

        emit PoolInitialized(poolId, owner, asset);
        emit RateModelUpdated(poolId, rateModel);
        emit PoolCapSet(poolId, poolCap);
    }

```
The `initializePool` function is vulnerable to a frontrunning attack. A malicious actor can observe a legitimate transaction in the mempool and create a pool with the same parameters but with a very low `poolCap`.

note : submitting this as high,because this attack has very low complexcity and this issue makes owners to spend more on Pool initialization and  again calling the `setPoolCap` to adjust the poolCap.

## Impact

1. **DOS**
* The legitimate user who intended to initialize the pool with specific parameters will be unable to do so because the malicious actor has already created a pool with the same parameters but with a very low poolCap.
* This results in the legitimate user's transaction failing, effectively preventing them from initializing the pool as intended.
2. **Increased Cost for Owner**
* To rectify the situation, the legitimate owner will have to call the setPoolCap function to update the poolCap of the pool that was initialized by the malicious actor.
* This additional step incurs extra gas costs, making the process more expensive for the legitimate owner.

```solidity
Example Scenario

**Legitimate User's Intent:**

* Alice wants to initialize a new pool with the following parameters:
 owner: Alice's address (0xAlice)
 asset: Token address (0xToken)
 poolCap: 1,000,000 tokens
 rateModelKey: 0xRateModelKey

Alice sends a transaction to the initializePool function with these parameters.

**Malicious Actor's Frontrunning:**

* Bob, a malicious actor, monitors the mempool and sees Alice's transaction.
* Bob quickly sends his own transaction to the initializePool function with the same parameters but with a very low poolCap (e.g., 1 token).
 Since Bob's transaction is processed first, the pool is initialized with Bob's parameters.

**Impact on Alice:**
When Alice's transaction is processed, it fails because the pool with the same owner, asset, and rateModelKey already exists.
Alice is unable to initialize the pool as intended.
Additional Steps for Alice:

To rectify the situation, Alice must call the `setPoolCap` function to update the poolCap of the pool initialized by Bob.
This incurs additional gas costs and operational overhead for Alice.
```

## Code Snippet

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L556C5-L598C6

## Tool used

Manual Review

## Recommendation