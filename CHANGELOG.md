# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-01-15

### Added
- Initial release of the **smart-contract-audit** Agent Skill.
- `skill.md` methodology with YAML frontmatter and a 5-step audit workflow:
  scope & context, Impact × Likelihood severity model, a vulnerability checklist
  of 18+ classes (reentrancy, integer over/underflow, access control, oracle /
  price manipulation, flash loans, unchecked external calls, front-running/MEV,
  delegatecall & proxy storage collisions, uninitialized proxies, signature
  replay, `tx.origin` auth, unprotected `selfdestruct`, gas griefing / DoS,
  rounding & vault inflation, bad randomness, visibility, centralization, and
  ERC-20 integration pitfalls), each with SWC IDs where applicable, a red-flag
  quick scan, and a structured report output format with before/after snippets.
- Two instructive example reports: an ERC-20 staking review (reentrancy +
  access-control) and a UUPS proxy review (storage collision + uninitialized
  implementation).
- README with badges, install/usage, features, severity-threshold table, and
  cross-links to `tripwire` and `promptproof`.
- MIT license, `.gitignore`, GitHub Actions validation workflow, and a pure-stdlib
  skill validator.

[1.0.0]: https://github.com/Viprasol-Tech/smart-contract-audit/releases/tag/v1.0.0
