# Security Review: `StakingRewards` (ERC-20 staking)

**Reviewer:** AI-assisted audit (smart-contract-audit skill)
**Date:** 2025-01-15
**Commit / Address:** `examples/StakingRewards.sol` (illustrative)
**Chain / solc:** Ethereum mainnet, `solc 0.8.19`
**Scope:** `StakingRewards.sol` — a single-asset staking pool paying an ERC-20 reward.
**Out of scope / assumptions:** Reward and staking tokens are standard ERC-20s
(no fee-on-transfer / rebasing). The deployer is an EOA. OpenZeppelin v4.9 is used.

**Totals: 1 Critical · 1 High · 1 Medium · 2 Low · 1 Informational**

---

## The contract under review (excerpt)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract StakingRewards {
    IERC20 public stakingToken;
    IERC20 public rewardToken;
    address public owner;
    uint256 public rewardRate;

    mapping(address => uint256) public staked;
    mapping(address => uint256) public rewards;

    constructor(address _stake, address _reward) {
        stakingToken = IERC20(_stake);
        rewardToken = IERC20(_reward);
        owner = msg.sender;
    }

    function stake(uint256 amount) external {
        stakingToken.transferFrom(msg.sender, address(this), amount);
        staked[msg.sender] += amount;
    }

    // Pays out the caller's accrued ETH-denominated rewards, then unstakes.
    function exit() external {
        uint256 reward = rewards[msg.sender];
        uint256 amount = staked[msg.sender];

        // send native reward bonus first
        (bool ok, ) = msg.sender.call{value: reward}("");
        require(ok, "reward xfer failed");

        staked[msg.sender] = 0;
        rewards[msg.sender] = 0;
        stakingToken.transfer(msg.sender, amount);
    }

    function setRewardRate(uint256 newRate) external {
        rewardRate = newRate;
    }
}
```

---

## Findings Summary

| ID | Title | Severity | Location |
|----|-------|----------|----------|
| C-01 | Reentrancy in `exit()` drains staked balances | Critical | `StakingRewards.sol` `exit()` |
| H-01 | Missing access control on `setRewardRate()` | High | `StakingRewards.sol` `setRewardRate()` |
| M-01 | Unchecked ERC-20 return values (`transfer`/`transferFrom`) | Medium | `stake()`, `exit()` |
| L-01 | Floating pragma `^0.8.0` | Low | file-level |
| L-02 | No events emitted on state changes | Low | all state-changing fns |
| I-01 | EOA owner / centralization not documented | Informational | `owner` |

---

## [C-01] Reentrancy in `exit()` drains staked balances

- **Severity:** Critical (Impact: High × Likelihood: High)
- **Location:** `StakingRewards.sol` — `exit()`
- **SWC:** SWC-107
- **Description:** `exit()` performs a native-value external call
  (`msg.sender.call{value: reward}("")`) **before** zeroing `staked[msg.sender]`
  and `rewards[msg.sender]` and before the staking-token transfer. A malicious
  contract's `receive()` can re-enter `exit()` while its `staked`/`rewards`
  entries are still non-zero, repeating the payout and the eventual
  `stakingToken.transfer` against stale balances.
- **Impact:** A single attacker can repeatedly trigger the reward payout and
  unstake path, draining the contract's native balance and other stakers'
  principal. Total loss of pooled funds.
- **Proof of Concept (sketch):**
    1. Attacker stakes a small amount and accrues `rewards[attacker] = r`.
    2. Attacker calls `exit()` from a contract whose `receive()` re-enters `exit()`.
    3. Because state is zeroed only *after* the `call`, each re-entry sees the old
       non-zero `rewards`/`staked` and pays/transfers again.
    4. Loop until the contract is empty; attacker withdraws everything.
- **Recommendation:** Apply **checks-effects-interactions** (zero all state
  *before* any external call) and add a `nonReentrant` guard. Prefer
  pull-over-push for the reward.

```solidity
// AFTER
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

function exit() external nonReentrant {
    uint256 reward = rewards[msg.sender];
    uint256 amount = staked[msg.sender];

    staked[msg.sender] = 0;          // effects first
    rewards[msg.sender] = 0;

    if (amount > 0) stakingToken.safeTransfer(msg.sender, amount);
    if (reward > 0) {                 // interaction last
        (bool ok, ) = msg.sender.call{value: reward}("");
        require(ok, "reward xfer failed");
    }
}
```

- **References:** SWC-107; OpenZeppelin `ReentrancyGuard`; "The DAO" (2016).

---

## [H-01] Missing access control on `setRewardRate()`

- **Severity:** High (Impact: High × Likelihood: Medium)
- **Location:** `StakingRewards.sol` — `setRewardRate()`
- **SWC:** SWC-105 (unprotected critical function)
- **Description:** `setRewardRate()` has no owner/role check; it is `external` and
  callable by anyone. `rewardRate` directly governs reward economics.
- **Impact:** Any user can set the reward rate arbitrarily (e.g., to a huge value),
  manipulating reward accrual to over-pay themselves or grief the protocol's
  accounting — a direct economic attack.
- **Proof of Concept (sketch):** Attacker calls `setRewardRate(type(uint256).max)`
  immediately before claiming, inflating their own accrual.
- **Recommendation:** Gate behind `onlyOwner` (prefer `Ownable2Step`), and ideally
  a timelock + multisig for a parameter this sensitive.

```solidity
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

function setRewardRate(uint256 newRate) external onlyOwner {
    rewardRate = newRate;
    emit RewardRateUpdated(newRate);
}
```

- **References:** SWC-105; OpenZeppelin `Ownable2Step`.

---

## [M-01] Unchecked ERC-20 return values

- **Severity:** Medium (Impact: Medium × Likelihood: Medium)
- **Location:** `stake()` (`transferFrom`), `exit()` (`transfer`)
- **SWC:** SWC-104
- **Description:** Return values of `transferFrom`/`transfer` are ignored, and some
  real-world tokens (e.g., USDT) don't return a bool at all. A silent failure
  would credit a user without actually receiving tokens, or mark an unstake as
  done without delivering tokens.
- **Impact:** Accounting can diverge from real balances, leading to insolvency or
  stuck funds depending on the token.
- **Recommendation:** Use OpenZeppelin **`SafeERC20`** (`safeTransfer`,
  `safeTransferFrom`). If fee-on-transfer tokens must be supported, account on the
  measured `balanceAfter - balanceBefore`.
- **References:** SWC-104; OpenZeppelin `SafeERC20`.

---

## [L-01] Floating pragma `^0.8.0`

- **Severity:** Low
- **Description:** A floating pragma lets the contract compile under many compiler
  versions, including ones with known bugs or different behavior than tested.
- **Recommendation:** Pin to the audited/tested version, e.g. `pragma solidity 0.8.19;`.
- **References:** SWC-103.

---

## [L-02] No events emitted on state changes

- **Severity:** Low
- **Description:** `stake`, `exit`, and `setRewardRate` change state without
  emitting events, hindering off-chain monitoring and incident response.
- **Recommendation:** Emit `Staked`, `Exited`, and `RewardRateUpdated` events.

---

## [I-01] EOA owner / centralization not documented

- **Severity:** Informational
- **Description:** Privileged control (once `setRewardRate` is gated) rests with a
  single EOA. A compromised key is a single point of failure.
- **Recommendation:** Use a multisig + timelock; document the owner's powers
  honestly to users.

---

## Gas & Optimization Notes (non-security, lower priority)

- Cache `staked[msg.sender]` / `rewards[msg.sender]` into locals (done in the fix)
  to avoid repeated `SLOAD`s.
- Use custom errors instead of `require` strings to save deployment + revert gas.
- Mark `stakingToken` / `rewardToken` `immutable` (set once in the constructor).

---

> **Disclaimer.** This is an **AI-assisted security review**, not a professional
> audit. It may produce false positives and miss real vulnerabilities — especially
> complex economic, cross-contract, and protocol-design issues. Do **not** deploy
> to mainnet or move real value based on this review alone. Complement with
> **Slither**, **Mythril**, **Echidna/Foundry** invariant fuzzing, comprehensive
> tests, a professional audit, and a bug bounty.
