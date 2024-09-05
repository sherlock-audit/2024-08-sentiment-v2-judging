Broad Pecan Troll

Medium

# `deploySuperPool` function is suspicious of the reorg attack.

## Summary

## Vulnerability Detail
The `deploySuperPool` function deploys a super pool contract using the create, where the address derivation depends only on SuperPoolFactory nonce.

At the same time, some of the chains (Polygon, Optimism, Arbitrum) to which the QuestFactory will be deployed are suspicious of the reorg attack. 

Since the contract's can be delyoed on.
> On what chains are the smart contracts going to be deployed?

> Any EVM-compatbile network

A very clear example to consider would be Polygon:
Please note, reorg on Polygon happens really often. Some are 1 block long, some are >5 minutes long. For the latest, it is quite enough to create the dao and transfer funds to it, especially when someone uses a script, and not doing it by hand.


- [Visit](https://polygonscan.com/blocks_forked)

![helo](https://github.com/user-attachments/assets/063414a0-ef5c-4cb8-a149-7ffe6b0dfa9b)

Here you may be convinced that the Polygon has in practice subject to reorgs. Even more, the reorg on the picture is 1.5 minutes long. So, it is quite enough to create the quest and transfer funds to that address, especially when someone uses a script, and not doing it by hand.

Optimistic rollups (Optimism/Arbitrum) are also suspect to reorgs since if someone finds a fraud the blocks will be reverted, even though the user receives a confirmation and already created a quest.

Attack scenario:
Imagine that Alice deploys a super pool contract first, and then sends funds to it. Bob sees that the network block reorg happens and calls `deploySuperPool`. Thus, it creates super pool with an address to which Alice sends funds. Then Alices' transactions are executed and Alice transfers funds to Bob's controlled super pool.

## Impact
If users rely on the address derivation in advance or try to deploy the wallet with the same address on different EVM chains, any funds sent to the wallet could potentially be withdrawn by anyone else. All in all, it could lead to the theft of user funds.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPoolFactory.sol#L56C4-L81C2

## Tool used

Manual Review

## Recommendation
Deploy the super pool contract via `create2` with `salt` that includes `msg.sender`/`owner`.
