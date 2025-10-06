# Compliance Token

The Compliance Token is an implementation of the ERC-3643 token interface as well as the Cross-Chain Identity interface
and Policy Management interface, as defined in this repository.

The following are the differences between this ERC-3643 implementation and the canonical T-Rex implementation:

- Utilizes the [Cross-Chain Identity](../../cross-chain-identity/README.md) package defined in this repository as the identity system instead of ONCHAINID.
- Utilizes the [Policy Management](../../policy-management/README.md) package defined in this repository as the policy management system instead of the T-Rex `ModularCompliance` system.

## Frozen Token Behavior

This ERC-3643 implementation follows the standard T-REX approach to frozen tokens during burns and forced transfers:

- **Automatic Unfreezing**: When burning or force transferring tokens, if there are insufficient unfrozen tokens, the contract automatically unfreezes the required amount to complete the operation.
- **Flexible Operations**: This allows administrative operations to proceed even when tokens are frozen, providing operational flexibility.

**Comparison with ERC-20 Implementation:**
Unlike the [ERC-20 compliance token](../erc-20/) in this repository, which preserves frozen status during all operations, this ERC-3643 implementation prioritizes operational flexibility by automatically managing frozen balances as needed.

Choose the implementation that best fits your compliance requirements:

- **ERC-3643**: For operational flexibility with automatic frozen token management
- **ERC-20**: For strict frozen token preservation and explicit control
