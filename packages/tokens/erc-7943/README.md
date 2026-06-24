# Compliance Token ERC-7943

The Compliance Token ERC-7943 is an implementation of the [ERC-7943 Universal RWA Interface](https://eips.ethereum.org/EIPS/eip-7943) as well as the Policy Management interface defined in this repository.

ERC-7943 (uRWA) defines a minimal, unopinionated interface for tokenized Real World Assets (RWAs), providing standard functions for compliance checks, transfer controls, and enforcement actions while remaining compatible with existing token standards like ERC-20.

## Features

This implementation provides the following ERC-7943 compliant features:

### Whitelist Management (`canSend`, `canReceive`)
- Send- and receive-eligibility are tracked in **separate whitelists**, enabling one-way restrictions (e.g. an account blocked from receiving but still allowed to send), as described by EIP-7943
- `canSend()` checks the send whitelist; `canReceive()` checks the receive whitelist
- Both directions are set in one call, policy-protected via `changeWhitelist(account, sendAllowed, receiveAllowed)`

### Token Freezing (`getFrozenTokens`, `setFrozenTokens`)
- Administrators can freeze tokens in user accounts
- `setFrozenTokens()` overwrites the frozen amount (similar to ERC-20's `approve`)
- Supports "pre-freezing" tokens before they are received
- Users cannot transfer more than their unfrozen balance

### Transfer Validation (`canTransfer`)
- `canTransfer()` checks if a transfer would succeed
- Validates whitelist status of both sender and recipient
- Ensures sufficient unfrozen balance exists

### Forced Transfers (`forcedTransfer`)
- Administrative function for regulatory compliance or recovery scenarios
- Automatically unfreezes tokens if transfer amount exceeds unfrozen balance
- Requires recipient to be whitelisted
- Policy-protected for authorization control

## Frozen Token Behavior

This ERC-7943 implementation follows a flexible approach to frozen tokens during administrative operations:

- **Automatic Unfreezing**: When performing a forced transfer or administrative burn, if there are insufficient unfrozen tokens, the contract automatically reduces the frozen amount to complete the operation.
- **Operational Flexibility**: This allows administrative operations to proceed even when tokens are frozen, providing flexibility for compliance scenarios.

**Comparison with Other Implementations:**

| Feature | ERC-7943 | [ERC-20](../erc-20/) | [ERC-3643](../erc-3643/) |
|---------|----------|----------------------|--------------------------|
| Whitelist | Built-in | Not included | Via Identity Registry |
| Frozen Tokens | Auto-unfreeze on admin ops | Strict preservation | Auto-unfreeze on admin ops |
| Admin Burns | Can burn frozen tokens | Cannot burn frozen | Can burn frozen tokens |
| Force Transfer | Can transfer frozen | Can transfer frozen | Can transfer frozen |

## Policy Protection

All sensitive operations are protected by the Policy Engine:

| Function | Description | Typical Policy |
|----------|-------------|----------------|
| `mint` | Create new tokens | OnlyAuthorizedSender |
| `burn` | Destroy tokens (own balance) | OnlyAuthorizedSender |
| `burnFrom` | Destroy tokens (any account) | OnlyOwner |
| `forcedTransfer` | Administrative transfer | OnlyOwner |
| `setFrozenTokens` | Freeze/unfreeze tokens | OnlyAuthorizedSender |
| `changeWhitelist` | Manage whitelist | OnlyOwner |

## Interface

The ERC-7943 Fungible interface defines:

```solidity
interface IERC7943Fungible is IERC165 {
    // Events
    event ForcedTransfer(address indexed from, address indexed to, uint256 amount);
    event Frozen(address indexed account, uint256 amount);

    // Errors
    error ERC7943CannotSend(address account);
    error ERC7943CannotReceive(address account);
    error ERC7943CannotTransfer(address from, address to, uint256 amount);
    error ERC7943InsufficientUnfrozenBalance(address account, uint256 amount, uint256 unfrozen);

    // Functions
    function forcedTransfer(address from, address to, uint256 amount) external returns (bool);
    function setFrozenTokens(address account, uint256 amount) external returns (bool);
    function canSend(address account) external view returns (bool);
    function canReceive(address account) external view returns (bool);
    function getFrozenTokens(address account) external view returns (uint256);
    function canTransfer(address from, address to, uint256 amount) external view returns (bool);
}
```

## ERC-165 Interface Support

The contract supports interface detection via ERC-165:

- `IERC7943Fungible`: `0x3edbb4c4`
- `IERC20`: `0x36372b07`
- `IERC165`: `0x01ffc9a7`

## Extractors

The following extractors are provided for policy engine integration:

| Extractor | Functions | Parameters |
|-----------|-----------|------------|
| `ERC7943MintBurnExtractor` | mint, burn, burnFrom | account, amount |
| `ERC7943ForcedTransferExtractor` | forcedTransfer | from, to, amount |
| `ERC7943SetFrozenTokensExtractor` | setFrozenTokens | account, amount |
| `ERC7943WhitelistExtractor` | changeWhitelist | account, sendAllowed, receiveAllowed |

Standard ERC-20 transfer functions use the `ERC20TransferExtractor`.

## Usage Example

```solidity
// Deploy token
ComplianceTokenERC7943 token = new ComplianceTokenERC7943();
token.initialize("My RWA Token", "RWA", 18, address(policyEngine));

// Whitelist users (sendAllowed, receiveAllowed)
token.changeWhitelist(alice, true, true);
token.changeWhitelist(bob, true, true);

// Mint tokens
token.mint(alice, 1000);

// Check if transfer would succeed
bool allowed = token.canTransfer(alice, bob, 500);

// Freeze some tokens
token.setFrozenTokens(alice, 200);

// Alice can now only transfer 800 tokens (1000 - 200 frozen)
// Check available balance
uint256 frozen = token.getFrozenTokens(alice);
uint256 available = token.balanceOf(alice) - frozen;

// Administrative forced transfer (can move frozen tokens)
token.forcedTransfer(alice, bob, 900);
```

## Deployment

Use the provided deployment script:

```bash
PRIVATE_KEY=<your_key> TOKEN_NAME="My Token" TOKEN_SYMBOL="MTK" forge script script/DeployComplianceTokenERC7943.s.sol --broadcast
```

## See Also

- [ERC-7943 Specification](https://eips.ethereum.org/EIPS/eip-7943)
- [Policy Management](../../policy-management/README.md)
- [Cross-Chain Identity](../../cross-chain-identity/README.md)
