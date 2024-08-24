Soaring Malachite Trout

Medium

# Lack of Factory Deployment Check in `SuperPool` Constructor Allows Unauthorized Deployments

## Summary
The current `SuperPool` constructor allows for the deployment of `SuperPool` contracts outside of the designated factory. This introduces a risk where unauthorized users might deploy `SuperPool` contracts that point to malicious or unintended pool implementations. The constructor does not verify if the deployment is being performed by the factory contract, which could lead to security issues and difficulty in distinguishing between legitimate and malicious `SuperPool` instances.


## Vulnerability Detail
1. **Lack of Factory Verification in Constructor:**
   - **Issue:** The `SuperPool` contract does not include a check to verify if it is being deployed by an authorized factory contract. This oversight means that anyone can deploy a `SuperPool` instance, potentially pointing to a malicious `POOL` or `ASSET` contract.
   - **Potential Impact:** Users interacting with the `SuperPool` could inadvertently interact with a malicious pool, especially if there are multiple `SuperPools` with the same asset but differing in legitimacy. This issue can also complicate the user experience and increase the risk of interacting with fraudulent contracts.

   ```solidity
   constructor(
       address pool_,
       address asset_,
       address feeRecipient_,
       uint256 fee_,
       uint256 superPoolCap_,
       string memory name_,
       string memory symbol_
   ) Ownable() ERC20(name_, symbol_) {
       POOL = Pool(pool_);
       ASSET = IERC20(asset_);
       DECIMALS = _tryGetAssetDecimals(ASSET); // What if it couldn't get the decimals?

       if (fee > 1e18) revert SuperPool_FeeTooHigh();
       fee = fee_;
       feeRecipient = feeRecipient_;
       superPoolCap = superPoolCap_;
   }
   ```

## Impact

- **Security Risk:** Malicious users could deploy `SuperPool` contracts that might point to harmful or compromised pool contracts, potentially leading to loss of assets or security breaches.
- **User Confusion:** Users might find it difficult to distinguish between legitimate and malicious `SuperPools`, especially if multiple `SuperPools` are associated with the same asset.
- **Integrity of Deployment:** The lack of factory verification undermines the integrity of the deployment process, which was intended to ensure all `SuperPools` point to the same secure implementation.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L144
## Tool used

Manual Review

## Recommendation

- **Implement Factory Check:**
  - Add a modifier to the `SuperPool` contract that restricts deployment to only the authorized factory contract. This ensures that only the factory can deploy new instances of `SuperPool`.

  ```solidity
  modifier onlyFactory() {
      require(msg.sender == factoryAddress, "Not authorized factory");
      _;
  }
  ```

- **Update Constructor:**
  - Include the factory address as a parameter and set it in the constructor. Use the `onlyFactory` modifier to restrict deployment.

  ```solidity
  address public factoryAddress;

  constructor(
      address pool_,
      address asset_,
      address feeRecipient_,
      uint256 fee_,
      uint256 superPoolCap_,
      string memory name_,
      string memory symbol_,
      address factory_
  ) Ownable() ERC20(name_, symbol_) {
      require(msg.sender == factory_, "Not authorized factory");
      POOL = Pool(pool_);
      ASSET = IERC20(asset_);
      DECIMALS = _tryGetAssetDecimals(ASSET);

      if (fee > 1e18) revert SuperPool_FeeTooHigh();
      fee = fee_;
      feeRecipient = feeRecipient_;
      superPoolCap = superPoolCap_;
      factoryAddress = factory_;
  }
  ```