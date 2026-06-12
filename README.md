# smart-contract-audit

> An Agent Skill that turns your AI coding assistant into a disciplined first-pass **smart-contract security auditor** — scope, severity-rate, and fix Solidity/EVM vulnerabilities, grounded in the SWC Registry and real DeFi exploit history.

[![GitHub stars](https://img.shields.io/github/stars/Viprasol-Tech/smart-contract-audit?style=social)](https://github.com/Viprasol-Tech/smart-contract-audit/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Agent Skills](https://img.shields.io/badge/Agent%20Skills-Compatible-8A2BE2)](https://github.com/Viprasol-Tech/smart-contract-audit)
[![SWC Registry](https://img.shields.io/badge/SWC%20Registry-37%20Weaknesses-green)](https://swcregistry.io/)
[![Version](https://img.shields.io/badge/version-1.0.0-blue)](CHANGELOG.md)

**Works with:** Claude Code · OpenAI Codex · Cursor · GitHub Copilot · Gemini CLI · 26+ Agent Skills-compatible tools.

---

## Quick Install

Clone into your agent's skills directory:

```bash
# Claude Code
git clone https://github.com/Viprasol-Tech/smart-contract-audit.git \
  ~/.claude/skills/smart-contract-audit

# OpenAI Codex
git clone https://github.com/Viprasol-Tech/smart-contract-audit.git \
  ~/.codex/skills/smart-contract-audit
```

For Cursor, Copilot, Gemini CLI, and other tools, drop the folder into that tool's
skills/rules directory (or point it at `skill.md`). The skill is a single portable
markdown methodology — no install step, no dependencies.

---

## Try It

In your agent, just ask:

```
Audit this ERC-20 staking contract for vulnerabilities
```

…and paste the contract (or share a file/repo/address). The skill will scope the
target, walk the vulnerability checklist, and return a severity-rated report with
exploit scenarios and concrete fixes.

---

## Why This Exists

DeFi has lost **billions** to preventable smart-contract bugs — reentrancy, oracle
manipulation, missing access control, uninitialized proxies. Most of these map to
well-known patterns in the **SWC Registry** and to repeated, documented exploit
classes. Yet the same mistakes ship again and again because a careful first-pass
review never happened before deployment.

This skill encodes a real auditor's methodology so your AI assistant doesn't just
say "looks fine" — it scopes the target, reasons about impact × likelihood, and
walks a comprehensive checklist with the discipline of a security engineer. It's
the review you should run **before** you pay for a professional audit, not instead
of one.

---

## What It Does

- **Scopes** the target — chain, `solc` version, framework, upgradeability, value
  at risk, trust model, and which contracts are actually in scope.
- **Severity-rates** every finding on an explicit **Impact × Likelihood** matrix
  (Critical / High / Medium / Low / Informational).
- **Walks ≥18 vulnerability classes** — each with *what it is → how to spot it →
  exploit scenario → the fix/pattern* — with **SWC IDs** where applicable.
- **Runs a red-flag quick scan** for instant danger signs (`tx.origin` auth,
  `delegatecall` to user input, missing modifiers, spot-price oracles, …).
- **Outputs a structured report** — summary table, per-finding detail with PoC
  sketches and fixes, gas/optimization notes, and a clear professional disclaimer.

---

## Features

| Feature | What you get |
|---|---|
| **Severity model** | Explicit Impact × Likelihood matrix; ties resolve toward higher severity when funds are at risk |
| **Vulnerability checklist** | ≥18 classes — reentrancy, integer over/underflow, access control, oracle/price manipulation, flash loans, unchecked calls, front-running/MEV, delegatecall & proxy storage collisions, uninitialized proxies, signature replay, `tx.origin` auth, unprotected `selfdestruct`, gas griefing/DoS, rounding/precision & vault inflation, bad randomness, visibility, centralization, ERC-20 integration pitfalls |
| **Red-flag scan** | Grep-able instant danger signs surfaced before the deep pass |
| **Gas notes** | Separate, clearly-lower-priority optimization section |
| **Tool-aware** | References Slither, Mythril, Echidna/Foundry as complements to run |

### Example severity thresholds

| Finding | Impact | Likelihood | Severity |
|---|---|---|---|
| Reentrancy drains the vault | High | High | **Critical** |
| Missing `onlyOwner` on a sensitive setter | High | Medium | **High** |
| DEX spot price used for collateral valuation | Medium | Medium | **Medium** |
| Floating pragma `^0.8.x` | Low | Medium | **Low** |
| Missing event on a parameter change | Low | Low | **Informational** |

---

## Examples

See full, instructive sample reports in [`examples/`](examples/):

- [`examples/erc20-staking-review.md`](examples/erc20-staking-review.md) — a vulnerable
  staking contract with a **reentrancy** drain and an **access-control** finding.
- [`examples/proxy-upgrade-review.md`](examples/proxy-upgrade-review.md) — a UUPS proxy
  with a **storage-collision** and an **uninitialized-implementation** finding.

---

## Pairs Well With

- **[tripwire](https://github.com/Viprasol-Tech/tripwire)** — runtime MCP poisoning / drift guard for AI agents.
- **[promptproof](https://github.com/Viprasol-Tech/promptproof)** — offline prompt-injection / jailbreak red-team test suite.

Use `smart-contract-audit` to harden the on-chain code, and the others to harden
the agents around it.

---

> This skill produces an **AI-assisted review** — a strong pre-audit and triage
> tool, **not** a substitute for a professional human audit, formal verification,
> fuzzing, and a bug bounty. Never deploy to mainnet based on this review alone.
> *This project is not affiliated with or endorsed by Anthropic; "Agent Skills
> compatible" refers to the open skill format.*

---

## Contact — Viprasol Tech Private Limited
- 🌐 Website: [viprasol.com](https://viprasol.com)
- ✉️ Email: [support@viprasol.com](mailto:support@viprasol.com)
- 💬 Telegram: [t.me/viprasol_help](https://t.me/viprasol_help) · 📱 WhatsApp: +91 96336 52112
- 🐙 GitHub: [@Viprasol-Tech](https://github.com/Viprasol-Tech) · 💼 [LinkedIn](https://www.linkedin.com/in/viprasol/) · 𝕏 [@viprasol](https://twitter.com/viprasol)

> *Viprasol Tech — fintech software, AI agents, algorithmic trading systems, and B2B SaaS.*

## License
[MIT](LICENSE) © 2025 Viprasol Tech Private Limited
