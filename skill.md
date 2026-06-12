---
name: smart-contract-audit
description: Audit Solidity/EVM smart contracts for security vulnerabilities — reentrancy, access control, oracle manipulation, and more. Grounded in the SWC Registry and real DeFi exploit patterns. Outputs severity-rated findings with exploit scenarios and fixes. Use for smart-contract security review, DeFi audits, or pre-deployment checks.
version: 1.0.0
---

# Smart Contract Security Audit

A structured methodology for reviewing Solidity / Vyper / EVM smart contracts and
producing a professional, severity-rated security report. This skill turns an
agent into a disciplined first-pass auditor: it scopes the target, walks a
comprehensive vulnerability checklist grounded in the **SWC Registry** and real
DeFi exploit history, and emits findings with exploit scenarios, proof-of-concept
sketches, and concrete fixes.

> This skill produces an **AI-assisted review**. It is a powerful pre-audit and
> triage tool, but it is **not** a substitute for a professional human audit.
> See the disclaimer at the end.

---

## When to Activate

Activate this skill when the user:

- Shares Solidity or Vyper source code (a file, a snippet, or a whole repo) and
  asks for a security review, audit, or "is this safe?".
- Provides a deployed **contract address** (mainnet or testnet) and asks what is
  wrong with it or how it could be exploited.
- Links a GitHub repo / Foundry / Hardhat project of contracts.
- Asks for a **pre-deployment checklist**, a "DeFi audit", or help finding
  reentrancy / oracle / access-control bugs.
- Is reviewing a protocol upgrade (proxy, UUPS, Diamond) for storage or
  initialization issues.

If you only have a contract **address** and no source, first try to obtain the
verified source (e.g., from a block explorer) or the bytecode. If neither is
available, state that clearly and limit the review to what the ABI / observable
behavior allows.

---

## Step 1: Scope & Context

Before reading a single line for bugs, establish context. Ask for — or infer and
state your assumptions about — each of the following. The right finding severity
depends entirely on this context.

| Question | Why it matters |
|---|---|
| **Target chain(s)** (Ethereum, Arbitrum, Base, BSC, Polygon, L2s…) | Gas semantics, opcode availability (`PUSH0`, `MCOPY`), reorg depth, and precompiles differ. L2 sequencers add downtime/oracle-staleness risks. |
| **Compiler / `solc` version** & `pragma` | `<0.8.0` has no built-in overflow checks. Specific versions have known compiler bugs (e.g., ABI head/tail, storage write removal). A floating `pragma ^0.8.x` is itself a finding. |
| **Framework** (Foundry, Hardhat, Truffle) & libraries (OpenZeppelin, Solmate, Solady) and their **versions** | Pin to known-vuln library versions; confirm `SafeERC20`, `ReentrancyGuard`, `Ownable2Step` etc. are the audited ones. |
| **Is it upgradeable?** (Transparent proxy, UUPS, Diamond/EIP-2535, Beacon) | Adds storage-layout, initializer, and `_authorizeUpgrade` attack surface. |
| **Value at risk / TVL** | Drives likelihood × impact. A bug in a contract holding $50M is Critical even if exploitation is fiddly. |
| **Trust model** | Who is privileged (owner, multisig, timelock, DAO)? Is the owner an EOA? Centralization is a finding when users are told it's "decentralized". |
| **External dependencies** | Oracles (Chainlink, Uniswap TWAP, custom), bridges, other protocols composed with. |
| **Which contracts are in scope** | Don't audit Oz's `ERC20.sol`; focus on the protocol's own logic and its integration points. |
| **Tests / coverage / prior audits** | Existing audit reports and invariants tell you where to dig deeper, not where to relax. |

Record the answers in a **Scope** block at the top of the report. State all
assumptions explicitly — an assumption that turns out wrong is itself worth
flagging.

---

## Step 2: Severity Model

Rate every finding on **Impact × Likelihood**. Use this matrix and resolve ties
toward the higher severity when funds are involved.

| | **Likelihood: High** | **Likelihood: Medium** | **Likelihood: Low** |
|---|---|---|---|
| **Impact: High** (funds drained / frozen, total loss of control) | **Critical** | **High** | **Medium** |
| **Impact: Medium** (partial loss, griefing, temporary DoS, unfair value extraction) | **High** | **Medium** | **Low** |
| **Impact: Low** (minor/cosmetic, requires implausible conditions) | **Medium** | **Low** | **Informational** |

**Severity definitions**

- **Critical** — Direct, practical theft or permanent freeze of user/protocol
  funds, or full takeover of privileged control. Must be fixed before any
  deployment. (e.g., unprotected `selfdestruct`, reentrancy draining the vault,
  uninitialized proxy implementation.)
- **High** — Loss of funds or critical functionality under realistic but
  constrained conditions, or requiring a specific (but reachable) state. (e.g.,
  oracle manipulation via spot price, missing access control on a sensitive
  setter.)
- **Medium** — Limited or conditional loss, griefing, recoverable DoS, or unfair
  value extraction (MEV). Or a High-impact issue gated behind a trusted role.
- **Low** — Minor issues, best-practice deviations with real but small impact,
  or issues needing implausible preconditions.
- **Informational** — No direct security impact: code quality, gas, style,
  missing events, documentation/centralization disclosure.

Also note **likelihood modifiers**: is the trigger permissionless? Does it need
a flash loan (cheap) vs. a large capital position (expensive)? Does it require
winning a race / specific block conditions? Account for these explicitly.

---

## Step 3: Vulnerability Checklist (by class)

Walk **every** class below against the in-scope code. For each, the format is:
*what it is → how to spot it → exploit scenario → fix/pattern*. SWC IDs are noted
where the Smart Contract Weakness Classification applies.

### 3.1 Reentrancy (SWC-107)
- **What:** An external call hands control to an attacker contract that re-enters
  the calling function before its state updates complete. Variants:
  single-function, cross-function (shared state), cross-contract, and
  **read-only reentrancy** (a view function returns stale state mid-callback,
  poisoning an integrating protocol).
- **Spot it:** An external call (`.call`, `.transfer`, token transfer, ERC-721/1155
  `safeTransfer*` hooks, ERC-777 `tokensReceived`) that happens **before** state
  (balances, shares, flags) is updated. Look for state writes after `.call{value:}`.
- **Exploit:** `withdraw()` sends ETH, then sets `balance[msg.sender] = 0`. The
  receiver's `receive()` calls `withdraw()` again with the old non-zero balance,
  looping until the contract is drained (classic "The DAO").
- **Fix:** **Checks-Effects-Interactions** — update all state *before* the external
  call. Add a `nonReentrant` guard (OpenZeppelin `ReentrancyGuard`). For
  read-only reentrancy, guard view functions or have integrators avoid trusting
  state during callbacks. Prefer **pull-over-push** withdrawals.

```solidity
// BEFORE (vulnerable)
function withdraw() external {
    uint256 bal = balances[msg.sender];
    (bool ok, ) = msg.sender.call{value: bal}("");   // interaction first
    require(ok);
    balances[msg.sender] = 0;                         // effect too late
}

// AFTER (checks-effects-interactions + guard)
function withdraw() external nonReentrant {
    uint256 bal = balances[msg.sender];
    balances[msg.sender] = 0;                         // effect first
    (bool ok, ) = msg.sender.call{value: bal}("");    // interaction last
    require(ok, "transfer failed");
}
```

### 3.2 Integer Overflow / Underflow (SWC-101)
- **What:** Arithmetic wraps around its type bounds.
- **Spot it:** `solc < 0.8.0` without SafeMath; any `unchecked { }` block; manual
  casts (`uint256` → `uint128`) that truncate; `a - b` where `b` may exceed `a`.
- **Exploit:** A balance subtraction underflows to a huge number, minting value
  from nothing; a downcast silently truncates a fee, accounting drift.
- **Fix:** Use `solc >= 0.8.x` (checked by default). Only use `unchecked` when you
  have **proven** bounds (e.g., loop counters). Use OZ `SafeCast` for downcasts.

### 3.3 Access Control / Missing Modifier (SWC-105, SWC-106)
- **What:** Sensitive functions (mint, pause, upgrade, withdraw, parameter
  setters, `selfdestruct`) callable by anyone, or by the wrong role.
- **Spot it:** State-changing or privileged functions with no `onlyOwner` /
  role check; `public`/`external` `init`/`setX`/`upgradeTo`; default-visibility
  functions (pre-0.5 implicitly public).
- **Exploit:** Anyone calls `setOracle()` to point the price feed at an
  attacker-controlled contract, then drains via mispricing.
- **Fix:** Apply `Ownable`/`AccessControl` modifiers; prefer `Ownable2Step` to
  avoid transferring ownership to a wrong/dead address; use a timelock + multisig
  for high-power roles. Verify **every** privileged path is gated.

### 3.4 Oracle / Price Manipulation
- **What:** Pricing off a manipulable source — a DEX **spot** price (`getReserves`,
  `balanceOf` of a pool), a single-block reading, or an oracle without freshness
  checks.
- **Spot it:** Spot price reads from Uniswap/Curve pools used directly; Chainlink
  reads that ignore `updatedAt`/`answeredInRound`/`answer <= 0`; using
  `totalSupply`/`balanceOf` as a price.
- **Exploit:** Flash-loan-skew the pool's reserves in one tx, borrow/redeem at the
  manipulated price, repay the flash loan, keep the difference (Harvest, Cheese
  Bank, bZx pattern).
- **Fix:** Use a manipulation-resistant oracle: Chainlink with staleness +
  min/max + L2 sequencer-uptime checks, or a Uniswap V3 **TWAP** over a meaningful
  window. Never price off single-block spot. Validate Chainlink rounds:
  `require(answer > 0 && updatedAt != 0 && block.timestamp - updatedAt < MAX_AGE)`.

### 3.5 Flash-Loan Attacks
- **What:** Not a bug per se, but an **amplifier** — attackers borrow unbounded
  capital atomically to satisfy any check that assumes "you can't have that much".
- **Spot it:** Logic that trusts balances, voting power, LP share, or price within
  a single transaction; governance that snapshots at `block.number` of the vote.
- **Exploit:** Borrow tokens to acquire majority voting power, pass a malicious
  proposal or drain via mispricing, repay — all atomically (Beanstalk).
- **Fix:** Use TWAP/checkpointed balances; snapshot voting power at a **past**
  block; add commit-reveal / timelocks to governance; never trust intra-tx
  balances as proof of stake.

### 3.6 Unchecked External Call Return Values (SWC-104)
- **What:** Low-level `.call`/`.send`/`.delegatecall` and non-reverting ERC-20
  `transfer`/`transferFrom` whose boolean result is ignored.
- **Spot it:** `token.transfer(...)` with no `require`; `(bool ok,)=addr.call(...)`
  where `ok` is unused; tokens like USDT that **don't return a bool**.
- **Exploit:** A "transfer" silently fails (or a weird token reverts/returns
  nothing), but the contract credits the user anyway — accounting is now wrong.
- **Fix:** Use OpenZeppelin **`SafeERC20`** (`safeTransfer`, `safeTransferFrom`,
  `forceApprove`) which handles non-standard tokens; always `require` the success
  of low-level calls.

### 3.7 Front-Running / MEV (SWC-114)
- **What:** Transactions are public in the mempool; searchers reorder/sandwich
  them for profit. Includes sandwich attacks on swaps and approval/setApproval
  races.
- **Spot it:** Swaps/mints without slippage protection (`amountOutMin`/deadline);
  auctions/claims decided by tx ordering; `approve` race condition.
- **Exploit:** User swaps with no `minOut`; a bot front-runs to move price, lets
  the victim swap at a bad rate, then back-runs — sandwiching the trade.
- **Fix:** Enforce user-supplied **slippage** (`amountOutMin`) and **deadline**;
  use commit-reveal for sensitive ordering; prefer `increaseAllowance`/
  `forceApprove` over bare `approve`; consider private mempools/MEV protection.

### 3.8 Delegatecall & Proxy Storage Collisions (SWC-112)
- **What:** `delegatecall` runs target code in the **caller's** storage/context.
  If the proxy and implementation disagree on storage layout, writes corrupt the
  wrong slots; `delegatecall` to attacker-controlled code is game over.
- **Spot it:** `delegatecall(userInput)`; proxy + implementation with mismatched
  state variable ordering; non-EIP-1967 storage slots; an implementation with its
  own constructor-set state.
- **Exploit:** A library `delegatecall`ed by a proxy declares `address owner` in
  slot 0, overwriting the proxy's own slot 0 — attacker becomes owner
  (Parity wallet freeze). Or `delegatecall` to user input that calls `selfdestruct`.
- **Fix:** Use audited proxy patterns (OZ Transparent / UUPS) with **EIP-1967**
  reserved slots and storage **gaps** (`uint256[50] __gap`). Never `delegatecall`
  to untrusted addresses. Keep storage layout append-only across upgrades.

### 3.9 Uninitialized Proxy / Initializer Issues
- **What:** Upgradeable contracts can't use constructors for proxy state, so they
  use an `initialize()`. If it's callable twice, or the implementation itself is
  left uninitialized, anyone can seize it.
- **Spot it:** `initialize()` without the `initializer` modifier or without
  disabling re-init; implementation contract not initialized / `_disableInitializers()`
  missing in its constructor; `_authorizeUpgrade` unprotected.
- **Exploit:** Attacker calls `initialize()` on the unguarded implementation,
  becomes its owner, then `upgradeToAndCall` → `selfdestruct`s the implementation,
  bricking every proxy that delegates to it (Parity-style).
- **Fix:** Use OZ `Initializable` with the `initializer` modifier; call
  `_disableInitializers()` in the implementation's constructor; protect
  `_authorizeUpgrade` with `onlyOwner`/role.

### 3.10 Signature Replay & Malleability (SWC-117, SWC-121, SWC-122)
- **What:** A signed message is accepted more than once, on another chain, or with
  a tweaked-but-valid `(r,s,v)`.
- **Spot it:** `ecrecover` without a **nonce**, without **`chainId`**, without a
  domain separator (EIP-712), without an expiry; not checking `s` is in the lower
  half-order; not checking recovered address `!= address(0)`.
- **Exploit:** A meta-transaction / permit signature with no nonce is replayed to
  execute the action repeatedly; or replayed on a forked chain.
- **Fix:** Use **EIP-712** typed data with a domain separator binding `chainId`
  and contract address; track per-signer **nonces**; include a deadline; use OZ
  `ECDSA.recover` (rejects malleable `s` and zero address). Consider EIP-2612
  `permit` from a vetted library.

### 3.11 tx.origin Authentication (SWC-115)
- **What:** Using `tx.origin` for auth instead of `msg.sender`.
- **Spot it:** `require(tx.origin == owner)`.
- **Exploit:** Victim is phished into calling a malicious contract; that contract
  calls the target — `tx.origin` is still the victim, so the check passes and the
  attacker acts as the victim.
- **Fix:** Authenticate with **`msg.sender`**. Reserve `tx.origin` only for the
  narrow "is this an EOA" heuristic (and even that is discouraged post-EIP-3074/7702).

### 3.12 Unprotected selfdestruct / Ether Withdrawal (SWC-106)
- **What:** `selfdestruct`/`SELFDESTRUCT` (or a withdraw-all) reachable by anyone.
- **Spot it:** `selfdestruct(...)` not gated by a role; arbitrary `delegatecall`
  that could reach one; "kill"/"destroy" functions.
- **Exploit:** Anyone destroys the contract, forwarding its balance to themselves
  and bricking dependents.
- **Fix:** Gate behind `onlyOwner`/multisig+timelock, or remove it. Note post-Dencun
  (EIP-6780) `selfdestruct` only fully deletes within the same tx as creation —
  don't rely on its old semantics either.

### 3.13 Denial of Service: Unbounded Loops & Gas Griefing (SWC-128, SWC-113)
- **What:** Loops over user-growable arrays can exceed the block gas limit; a
  single failing recipient in a push-payment loop blocks everyone (DoS with
  revert).
- **Spot it:** `for` over a dynamic array that anyone can grow; distributing funds
  by iterating recipients with `transfer`; external calls inside loops.
- **Exploit:** Attacker registers thousands of entries so the loop always
  out-of-gases; or a contract recipient that reverts on receive freezes a
  distribution.
- **Fix:** **Pull-over-push** (each user withdraws their own share); bound or
  paginate loops; cap array growth; isolate failing transfers so one can't block
  the rest.

### 3.14 Rounding / Precision Loss & First-Depositor (Vault Inflation)
- **What:** Integer division truncates; ordering of mul/div changes results.
  ERC-4626-style vaults are vulnerable to a first-depositor share-inflation attack.
- **Spot it:** `a / b * c` (divide before multiply); share = `assets * supply /
  totalAssets` with a zero/one-wei starting supply; fee math that rounds in the
  user's favor.
- **Exploit:** Attacker mints 1 wei of shares, then "donates" a large amount to
  the vault to inflate share price so the next depositor's deposit rounds down to
  **0 shares** — the attacker redeems and steals it.
- **Fix:** Multiply before dividing; round **against** the user for protocol-favoring
  math; seed initial shares / use virtual shares & assets (OZ ERC4626 `_decimalsOffset`)
  or a dead-shares mint to neutralize the inflation attack.

### 3.15 Bad Randomness (SWC-120)
- **What:** On-chain "randomness" from predictable values.
- **Spot it:** `block.timestamp`, `blockhash`, `block.prevrandao`/`difficulty`,
  `block.number`, or `keccak256` of those used to pick winners/mint rarity.
- **Exploit:** A miner/validator or a contract computing the same value in the
  same block predicts or biases the outcome and always wins.
- **Fix:** Use a verifiable randomness source (**Chainlink VRF**) or commit-reveal
  with economic bonds. Never derive value-bearing randomness from block fields.

### 3.16 Default / Incorrect Visibility & Uninitialized Storage (SWC-100, SWC-108, SWC-109)
- **What:** Functions/state with unintended visibility; uninitialized local
  storage pointers aliasing slot 0.
- **Spot it:** Missing visibility specifiers (older solc); `public` state that
  should be `private`/`internal`; a local `struct`/`array` storage variable
  declared without assignment.
- **Exploit:** An uninitialized storage pointer writes to slot 0 (often `owner`),
  hijacking it; or a publicly-exposed internal function is abused.
- **Fix:** Always specify visibility; mark sensitive state non-public; initialize
  storage references or use `memory` explicitly. Modern `solc` warns on these.

### 3.17 Centralization & Privileged-Role Risk
- **What:** Owner/admin can rug — mint infinitely, pause withdrawals, upgrade to
  malicious code, drain via a "rescue" function.
- **Spot it:** EOA owner; `mint` by owner with no cap; `pause` with no time bound;
  upgradeable with no timelock; `rescueTokens` that can take user funds.
- **Exploit:** A compromised or malicious key drains/freezes the protocol.
- **Fix:** Multisig + timelock for admin; document powers honestly; cap/limit
  privileged actions; consider renouncing or constraining upgradeability.

### 3.18 ERC-20 Integration Pitfalls (fee-on-transfer, rebasing, return values, decimals)
- **What:** Assuming all ERC-20s behave "normally."
- **Spot it:** Accounting on the **input** amount instead of the measured received
  balance; assuming 18 decimals; assuming `transfer` returns a bool / reverts.
- **Exploit:** A **fee-on-transfer** token delivers less than `amount`, but the
  contract credits the full `amount` → insolvency; a **rebasing** token changes
  balances out from under the accounting.
- **Fix:** Measure `balanceBefore`/`balanceAfter` for deposits; use `SafeERC20`;
  read `decimals()`; explicitly allow-list supported tokens; document unsupported
  token types.

---

## Step 4: Red-Flags Quick Scan

Before (and alongside) the deep pass, grep the codebase for these instant danger
signs. Any hit is at minimum a question, often a finding:

- `tx.origin` used for authorization.
- `delegatecall` / `callcode` — especially to a non-constant / user-supplied address.
- `selfdestruct` / `suicide` not behind a strict access check.
- `.call{value:}` / `.call(` whose return value is unused, or before state updates.
- Token `transfer`/`transferFrom`/`approve` **not** via `SafeERC20`.
- `block.timestamp`, `blockhash`, `block.prevrandao`, `now` used for randomness or
  tight time logic.
- `ecrecover` without nonce / `chainId` / EIP-712 / `s`-malleability / zero-address check.
- Unbounded `for`/`while` over a user-growable array; external calls inside loops.
- Missing `onlyOwner`/role modifier on `initialize`, `upgradeTo`, `setX`, `mint`,
  `pause`, `withdraw`, `rescue`.
- Floating pragma (`^`) or `solc < 0.8.0` without SafeMath.
- `unchecked { }` blocks — verify the bounds are actually safe.
- Proxy without EIP-1967 slots / storage `__gap`; implementation without
  `_disableInitializers()`.
- DEX **spot** price (`getReserves`, pool `balanceOf`) used as an oracle.
- Chainlink read ignoring `updatedAt` / `answer <= 0` / round completeness.
- Divide-before-multiply; vault share math with no first-deposit protection.
- `payable` fallback/`receive` with side effects; `assert` used for input
  validation (consumes all gas pre-0.8 / signals invariant break).
- Hardcoded addresses, secrets, or private keys; `console.log`/debug left in.

---

## Step 5: Output Format

Produce a single, well-structured report. Use this exact skeleton.

### 5.1 Header & Scope
```
# Security Review: <Project / Contract name>
**Reviewer:** AI-assisted audit (smart-contract-audit skill)
**Date:** <date>
**Commit / Address:** <hash or 0x…>
**Chain / solc:** <e.g., Ethereum mainnet, solc 0.8.24>
**Scope:** <files / contracts in scope>
**Out of scope / assumptions:** <list>
```

### 5.2 Findings Summary Table
A one-glance table, sorted by severity:

| ID | Title | Severity | Location |
|----|-------|----------|----------|
| C-01 | Reentrancy in `withdraw()` drains vault | Critical | `Vault.sol:142` |
| H-01 | Missing `onlyOwner` on `setRewardRate()` | High | `Staking.sol:88` |
| M-01 | Spot price used for collateral valuation | Medium | `Lending.sol:210` |
| L-01 | Floating pragma `^0.8.0` | Low | `*.sol` |
| I-01 | Missing event on parameter change | Informational | `Config.sol:55` |

Use ID prefixes `C-/H-/M-/L-/I-`. Include a count line, e.g.
`Totals: 1 Critical · 1 High · 1 Medium · 1 Low · 1 Informational`.

### 5.3 Per-Finding Detail
For **each** finding:

```
### [C-01] Reentrancy in `withdraw()` drains the vault
- **Severity:** Critical (Impact: High × Likelihood: High)
- **Location:** `Vault.sol:142-150`
- **SWC:** SWC-107
- **Description:** The external ETH transfer occurs before `balances[msg.sender]`
  is zeroed, allowing a malicious receiver to re-enter `withdraw()` and withdraw
  repeatedly against a stale balance.
- **Impact:** Complete drain of all ETH held by the contract.
- **Proof of Concept (sketch):**
    1. Attacker deposits 1 ETH.
    2. Attacker's contract `receive()` calls `Vault.withdraw()` again.
    3. Loop continues until `Vault` balance is 0; attacker withdraws ~all funds.
- **Recommendation:** Apply checks-effects-interactions (zero the balance before
  the transfer) and add OpenZeppelin `nonReentrant`. (Show before/after.)
- **References:** SWC-107; OpenZeppelin ReentrancyGuard; "The DAO" 2016.
```

Order findings by severity (Critical → Informational). Keep PoCs to the
minimal sketch needed to make the bug undeniable; don't write weaponized exploits.

### 5.4 Gas & Optimization Notes
A short, separate, **non-security** section (clearly labeled lower priority):
- `storage` reads cached into `memory` inside loops; `++i` in `unchecked` loop
  increments; `calldata` over `memory` for external array params; `immutable`/
  `constant` for never-changing values; custom errors over `require` strings;
  packing storage variables; avoiding redundant SLOADs. Note each only if it
  actually applies.

### 5.5 Disclaimer (always include verbatim spirit)
> **Disclaimer.** This is an **AI-assisted security review**, not a professional
> audit. It may produce false positives and, more importantly, **miss real
> vulnerabilities** — especially complex economic, cross-contract, and
> protocol-design issues. Automated and AI reviews do not replace a manual audit
> by a qualified firm, formal verification, comprehensive testing/fuzzing, and a
> bug bounty. **Do not deploy to mainnet or move real value based on this review
> alone.** Always complement with tooling — **Slither** (static analysis),
> **Mythril** (symbolic execution), and **Echidna**/**Foundry invariant fuzzing**
> — and an independent professional audit.

---

## Working Notes for the Agent

- **Be specific.** Cite exact file:line locations and the offending snippet. Vague
  findings are useless to fixers.
- **Be honest about confidence.** If something is suspicious but you can't confirm
  exploitability (e.g., depends on an out-of-scope contract), say so and rate
  likelihood accordingly — don't inflate.
- **Don't hallucinate APIs.** If you're unsure a library function exists or behaves
  as stated, flag the assumption.
- **Think like an attacker, report like an engineer.** Find the worst case, then
  give a clean, minimal, idiomatic fix.
- **Reference real tooling as complements,** not competitors: Slither for fast
  static coverage, Mythril for symbolic paths, Echidna/Foundry for property-based
  fuzzing and invariants. Recommend running them.
- **Never deploy advice.** Always end with the disclaimer; never tell a user a
  contract is "safe to deploy."
