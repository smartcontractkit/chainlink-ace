# Contributing to Chainlink ACE Core Contracts

Thanks for your interest in contributing!

## Quick start (local dev)

### Prerequisites

- **Node.js**: v18+ (CI uses Node 20)
- **pnpm**: v8 (matches CI)
- **Foundry**: version pinned in `.foundry-version`

> **Windows note**: Foundry is most reliable via **WSL2** on Windows. If you run into install/tooling issues on native Windows, use WSL2 and run commands from the Linux shell.

### Install + build

```bash
pnpm install
pnpm build
```

### Test + lint

```bash
pnpm test
pnpm run fmt:check
pnpm run lint
```

## Project layout

- `packages/policy-management/`: policy engine, base contracts, extractor/mapper system, policy library
- `packages/cross-chain-identity/`: CCID identity + credential registries and validator policy
- `packages/tokens/`: example policy-protected tokens (ERC-20 and ERC-3643)
- `getting_started/`: guided tutorials
- `script/`: Foundry deployment scripts

## Development guidelines

- **Solidity style**: run `pnpm fmt` (Foundry formatter) before opening a PR.
- **Tests required**: changes to contracts should include tests under the relevant `packages/*/test/` folder.
- **Keep interfaces stable**: prefer additive changes; call out breaking changes clearly.
- **Security mindset**: treat policy ordering, default allow/reject behavior, and “Allowed” short-circuiting as security-critical.

## Submitting a PR

1. Create a feature branch from `main`.
2. Keep PRs focused (one feature/fix per PR when possible).
3. Ensure:
   - `pnpm build`
   - `pnpm test`
   - `pnpm run fmt:check && pnpm run lint`
4. Include a short **Summary** and **Test plan** in the PR description.

## Reporting security issues

If you believe you’ve found a security vulnerability, please **do not** open a public issue. Instead, contact the maintainers privately (see `CODEOWNERS` in `.github/`).

