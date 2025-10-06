# Common Policies

- [AllowPolicy](#allowpolicy)
- [BypassPolicy](#bypasspolicy)
- [GrantorPolicy](#grantorpolicy)
- [IntervalPolicy](#intervalpolicy)
- [MaxPolicy](#maxpolicy)
- [OnlyAuthorizedSenderPolicy](#onlyauthorizedsenderpolicy)
- [OnlyOwnerPolicy](#onlyownerpolicy)
- [PausePolicy](#pausepolicy)
- [RejectPolicy](#rejectpolicy)
- [RoleBasedAccessControlPolicy](#rolebasedaccesscontrolpolicy)
- [SecureMintPolicy](#securemintpolicy)
- [VolumePolicy](#volumepolicy)
- [VolumeRatePolicy](#volumeratepolicy)

## Common Initialization Pattern

All policies in this repository follow a standard initialization pattern to ensure consistent configuration and deployment.

When a policy contract is deployed, it must be properly initialized using the following two-step process:

1. initialize(address policyEngine, address initialOwner, bytes configParams)

   - This function is part of the abstract Policy contract and must be called first.
   - It initializes the core components:
   - Sets the Policy Engine reference
   - Assigns ownership (OwnableUpgradeable)
   - Sets up any common inherited modules (ERC165Upgradeable, etc.)

2. configure(bytes configParams). Immediately after core initialization, the initialize function automatically calls configure(configParams).
   - Each policy implementation defines its own logic inside configure(bytes) to handle policy-specific parameters.
   - The configParams are expected to be ABI-encoded parameters.
   - For example, a policy that requires a maximum transfer quota might decode a single uint256 value from configParams.
   - Validation and state assignment happen inside configure().

Important: configure(bytes) is designed to be called only once during initialization.

## AllowPolicy

### Overview

The `AllowPolicy` implements access control through an allowlist. The policy immediately rejects the transaction if the `sender` is not on the list, halting any subsequent policy checks.

### Specific Configuration

1. **Allowlist Management**

   The contract [owner](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable.sol) can:

   - **`allowSender(address account)`**: Adds `account` to the allowlist.
   - **`disallowSender(address account)`**: Removes `account` from the allowlist.

2. **View Functions**
   - **`senderAllowed(address account) -> bool`**: Returns `true` if `account` is on the allowlist.

### Policy Parameters and Context

This policy expects a variable number of parameters, which are the addresses to check against the allowlist. Each parameter
MUST be an address. If ANY of the addresses provided are NOT present in the allowlist, the transaction will be rejected.

### Policy Behavior

- **`run(...)`**

  - Returns `PolicyResult.Rejected` if any of the parameters is not present on the allowlist.
  - Returns `PolicyResult.Continue` otherwise

- **`postRun(...)`**
  - Not implemented (no state changes required)

### Example Use Cases

- **Regulated Access**:  Provide access only to a select group of addresses.
- **Gradual Access**: Start with a restrictive allowlist, gradually adding trusted addresses.

## BypassPolicy

### Overview

The `BypassPolicy` implements access control through an allowlist. The policy immediately allows the transaction if the `sender` is on the list, bypassing any subsequent policy checks.

### Specific Configuration

1. **Allowlist Management**

   The contract [owner](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable.sol) can:

    - **`allowSender(address account)`**: Adds `account` to the allowlist.
    - **`disallowSender(address account)`**: Removes `account` from the allowlist.

2. **View Functions**
    - **`senderAllowed(address account) -> bool`**: Returns `true` if `account` is on the allowlist.

### Policy Parameters and Context

This policy expects a variable number of parameters, which are the addresses to check against the allowlist. Each parameter
MUST be an address. If ALL addresses provided are present in the allowlist, the transaction will be allowed, bypassing 
all subsequent policies.

### Policy Behavior

- **`run(...)`**

  - Returns `PolicyResult.Allowed` if all parameters are present on the allowlist
  - Returns `PolicyResult.Continue` otherwise

- **`postRun(...)`**
    - Not implemented (no state changes required)

### Example Use Cases

- **Privileged Access**: Allow specific addresses to bypass other policy checks.
- **Layered Permissions**: Combine with other policies—e.g., the transaction proceeds as normal unless the caller is on the allowlist.

## GrantorPolicy

### Overview

The `GrantorPolicy` requires a valid signature from an authorized signer (referred to as a "Grantor") for each transaction. The policy implements:

1. Signature validation from pre-approved signers
2. Time-based expiration checks
3. Nonce tracking to prevent replay attacks

The policy will reject transactions when:

- The signature is invalid
- The expiration time has passed
- The signer is not authorized
- The nonce has been previously used

### Specific Configuration

1. **Authorized Signers**

   The policy maps each signer address to a boolean in `s_signers`. The contract [owner](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable.sol) can:

   - Add signers with `addSigner(address)` which emits `SignerAdded(address)`
   - Remove signers with `removeSigner(address)` which emits `SignerRemoved(address)`

   Note: The contract deployer becomes the first signer during construction.

2. **Nonce Tracking**

   The policy maps each sender address to a nonce in `s_senderNonces`. This nonce is included in the hashed message that signers must sign and is incremented after each successful transaction.

   - **Initialization**: The nonce starts at `0` for each new sender.
   - **Usage**: When `run()` returns `PolicyResult.Continue` and the Policy Engine completes execution, `postRun(...)` increments the nonce.
   - **Replay Prevention**: Because the current nonce is part of the hashed message, reusing an old signature (which contains an outdated nonce) will produce a mismatch when the policy verifies the signature. Any stale nonce leads to an invalid signature, effectively preventing replay attacks.
   - **Visibility**: The current nonce for any address can be queried via `senderNonce(address)`.

3. **Expiration**

   The policy validates the `expiresAt` timestamp from the `GrantorContext` against `block.timestamp`. If `expiresAt < block.timestamp`, the policy returns `PolicyResult.Rejected`. This check ensures time-bound authorization.

   ```solidity
   if (grantorContext.expiresAt < block.timestamp) {
     return IPolicyEngine.PolicyResult.Rejected;
   }
   ```

4. **Message Signing**

   Messages are signed using EIP-191 personal sign format:

   ```solidity
   bytes32 messageHash = keccak256(abi.encode(
       from,
       to,
       amount,
       s_senderNonces[from],
       grantorContext.expiresAt
   )).toEthSignedMessageHash();

   (address signer,,) = ECDSA.tryRecover(
    message.toEthSignedMessageHash(),
    grantorContext.signature
   );
   ```

   Notes:

   - [`tryRecover`](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/ECDSA.sol#L56) validates the signature format and returns the recovered address `signer` (or `address(0)` if invalid). The policy only checks if `s_signers[signer]` is true, ignoring potential signature validation errors.
   - The signature is validated as an EIP-191 personal message (`eth_sign`), not EIP-712 typed data. Future implementation may use EIP-712 typed data.

### Policy Parameters and Context

The **GrantorPolicy** expects **three** `parameters` plus a `context` object. The parameters **must** be in the following order/format:

| Parameter Name | Type      | Description                                   |
| -------------- | --------- | --------------------------------------------- |
| `from`         | `address` | The address initiating the transfer (sender). |
| `to`           | `address` | The address receiving the transfer.           |
| `amount`       | `uint256` | The amount being transferred.                 |

The `context` is ABI-encoded data matching the following struct:

```solidity
struct GrantorContext {
    uint48 expiresAt;
    bytes signature;
}
```

- **`expiresAt (uint48)`**: A Unix timestamp (in seconds) after which the signature is invalid.
- **`signature (bytes)`**: The ECDSA signature proving an authorized signer approved this transaction.

### Policy Behavior

1. **`run(...)`**

   - Validates parameter count (must be exactly 3)
   - Decodes parameters and context
   - Checks if `expiresAt` timestamp is in the future
   - Constructs and verifies the message signature
   - Returns `PolicyResult.Continue` only if:
     - The signature is valid
     - The recovered signer is authorized
     - The expiration time hasn't passed
   - Returns `PolicyResult.Rejected` otherwise

2. **`postRun(...)`**
   - Can only be called by the Policy Engine
   - Validates parameter count (must be exactly 3)
   - Increments the nonce for the sender address decoded from the first parameter

### Example Use Cases

- **Authorized Transfers**: Require an external authority to sign off on "transfers" (or any custom action) before execution.
- **Time-limited Approvals**: The signer can impose a specific timeframe (`expiresAt`) for the validity of their signature.
- **Replay Protection**: Nonce increments ensure a signature can’t be reused in subsequent transactions.

## IntervalPolicy

### Overview

The `IntervalPolicy` limits transaction execution to specific **time slots** within a **repeating cycle**. The policy accepts or rejects transactions based on whether the **current slot** (derived from block time) falls within a configured **start slot** and **end slot**.

### Specific Configuration

- **Slot Duration (`s_slotDuration`)**  
  The length of each slot in seconds (e.g., `3600` for 1 hour, `86400` for 1 day).

- **Cycle Size (`s_cycleSize`)**  
  The total number of slots in each repeating cycle (e.g., `24` slots for 24 hours in a day, `7` slots for days in a week).

- **Cycle Offset (`s_cycleOffset`)**  
  An offset (in slots) added after computing the raw current slot. This shifts where slot `0` is effectively located in each cycle.

- **Start Slot (`s_startSlot`)** and **End Slot (`s_endSlot`)**  
  The inclusive and exclusive slot indices (within `[0, s_cycleSize)`) that define when transactions are permitted. A transaction is allowed only if the computed current slot is in `[s_startSlot, s_endSlot)`.

These values can be set in the constructor or changed by the contract [owner](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable.sol) via:

- `setStartSlot(uint256 _startSlot)`
- `setEndSlot(uint256 _endSlot)`
- `setCycleParameters(uint256 _slotDuration, uint256 _cycleSize, uint256 _cycleOffset)`

### Policy Parameters

| Parameter Name  | Type  | Description                                                                                                                                                        |
| --------------- | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| _No parameters_ | _N/A_ | The policy does not decode or use any parameters from the Extractor/Mapper. It relies solely on `block.timestamp` and its configured slot cycle to make decisions. |

Because `IntervalPolicy` ignores the `parameters` array passed into `run(...)`, it only uses the current block timestamp, combined with `s_slotDuration`, `s_cycleSize`, `s_cycleOffset`, etc., to determine if the transaction falls within the allowed slot range.

### Policy Behavior

- **`run(...)`**

  1. Computes the current slot as:
     ```solidity
     uint256 currentSlot =
       ((block.timestamp / s_slotDuration) % s_cycleSize + s_cycleOffset) % s_cycleSize;
     ```
  2. Returns `PolicyResult.Continue` if `currentSlot` is within `[s_startSlot, s_endSlot)`, otherwise `PolicyResult.Rejected`.

- **`postRun(...)`**
  - Not used in this policy (no state changes needed after `run`).

### Configuration Examples

1. **Daily Business Hours (9 AM - 5 PM UTC)**

   ```solidity
   new IntervalPolicy(
       9,       // startSlot = 9
       17,      // endSlot = 17
       3600,    // 1-hour slot duration
       24,      // 24 slots in each daily cycle
       0        // no cycle offset
   );

   ```

2. **Weekday Operations (Monday-Friday)**
   ```solidity
   new IntervalPolicy(
      1,       // startSlot = 1 (Monday)
      6,       // endSlot = 6 (Saturday, but exclusive -> stops before Saturday)
      86400,   // 1-day slot duration
      7,       // 7 slots in each weekly cycle
      0        // no cycle offset
   );
   ```

### Example Use Cases

- **Hourly or Daily Windows**: Permit specific hours in the day (e.g., 9 AM to 5 PM).
- **Weekly or Monthly Cycles**: Restrict transactions to certain days of the week or specific days in a month.
- **Maintenance Windows**: Automatically disallow transactions outside scheduled operating hours.

## MaxPolicy

### Overview

The `MaxPolicy` enforces a maximum value constraint. The policy compares a provided usage value against a configured maximum and rejects transactions that would exceed this limit.

For example, to enforce a maximum transfer amount of 1000 tokens:

```solidity
// Create policy that caps transfers at 1000 tokens
MaxPolicy transferCapPolicy = new MaxPolicy();
policy.initialize(address(policyEngine), owner, abi.encode(1000));

// Usage:
// used <= 1000: PolicyResult.Continue
// used > 1000:  PolicyResult.Rejected
```

### Specific Configuration

1. **Deployment Parameter**

   - **`uint256 max`**: The initial maximum. If a transaction's `amount` (`uint256`) value exceeds this value, the policy rejects the transaction.

2. **Owner Controls**

   - **`setMax(uint256 max)`**: Updates the maximum.
   - **`getMax()`**: Returns the current maximum.

The contract [owner](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable.sol) manages these functions.

### Policy Parameters

| Parameter Name | Type      | Description                                     |
| -------------- | --------- | ----------------------------------------------- |
| `amount`       | `uint256` | A usage value that must not exceed the maximum. |

No additional `context` is required.

### Policy Behavior

- **`run(...)`**

  - Expects exactly one parameter, `amount` (`uint256`).
  - Compares `amount` to the current `s_max`.
  - Returns `PolicyResult.Rejected` if `amount > s_max`.
  - Returns `PolicyResult.Continue` otherwise.

- **`postRun(...)`**
  - Not implemented (no state changes required).

### Example Use Cases

- **API Call Limits**: Restrict the number of calls or resource usage per transaction.
- **Token Spending Caps**: Enforce that a user does not exceed a certain token allowance in a single operation.
- **Resource Quotas**: Limit the maximum usage of onchain functionality in a one-off or per-transaction basis.

## OnlyAuthorizedSenderPolicy

### Overview

The `OnlyAuthorizedSenderPolicy` implements access control through an authorized list. The policy rejects the transaction if the `sender` is **NOT** on the list.

### Specific Configuration

1. **Authorized List Management**

   The contract [owner](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable.sol) can:

   - **`authorizeSender(address account)`**: Adds `account` to the authorized list.
   - **`unauthorizeSender(address account)`**: Removes `account` from the authorized list.

2. **View Functions**
   - **`senderAuthorized(address account) -> bool`**: Returns `true` if `account` is on the authorized list.

### Policy Parameters and Context

| Parameter Name  | Type  | Description                                                                                                                            |
| --------------- | ----- | -------------------------------------------------------------------------------------------------------------------------------------- |
| _No parameters_ | _N/A_ | This policy does **not** require any parameters from the Policy Engine's configured Extractor and Mapper. It checks `sender` directly. |

### Policy Behavior

- **`run(...)`**

  - Returns `PolicyResult.Continue` if `sender` is on the authorized list
  - Returns `PolicyResult.Rejected` otherwise

- **`postRun(...)`**
  - Not implemented (no state changes required)

### Example Use Cases

- **Restricted Access**: Only allow specific addresses operate the contract methods.

## OnlyOwnerPolicy

### Overview

The `OnlyOwnerPolicy` that only allows the policy owner to call the method, similar to `Ownable` from OpenZeppelin.

### Policy Parameters and Context

| Parameter Name  | Type  | Description                                                                                                                            |
| --------------- | ----- | -------------------------------------------------------------------------------------------------------------------------------------- |
| _No parameters_ | _N/A_ | This policy does **not** require any parameters from the Policy Engine's configured Extractor and Mapper. It checks `sender` directly. |

### Policy Behavior

- **`run(...)`**

  - Returns `PolicyResult.Continue` if `sender` is the owner of the policy
  - Returns `PolicyResult.Rejected` otherwise

- **`postRun(...)`**
  - Not implemented (no state changes required)

### Example Use Cases

- **Restricted Access**: Only allow contract deployer to operate the contract methods.

## PausePolicy

### Overview

The `PausePolicy` allows an [owner](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable.sol) to enable or disable ("pause") all transactions. When the policy is paused, all incoming transactions will be rejected. When unpaused, the policy defers the decision (returns `PolicyResult.Continue`) so that other policies or the default policy engine logic can take effect.

### Specific Configuration

1. **Deployment Parameter**

   - **`bool _paused`**: The initial pause state. If set to `true`, the policy starts off rejecting all transactions. If `false`, it starts in a "normal" state allowing transactions to continue.

2. **Owner Controls**

   - **`pause()`**: Sets the policy to a paused state (`s_paused = true`), rejecting all subsequent transactions.
   - **`unpause()`**: Resets the policy to an unpaused state (`s_paused = false`), allowing transactions to continue.

### Policy Parameters

| Parameter Name  | Type  | Description                                                                                                                                                                                 |
| --------------- | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| _No parameters_ | _N/A_ | The policy does not inspect or decode parameters from the Extractor/Mapper. It relies solely on its internal pause flag (`s_paused`) to decide whether to reject or continue a transaction. |

Since `PausePolicy` ignores the `parameters` array passed into `run(...)`, it uses the `s_paused` boolean to immediately reject transactions (`PolicyResult.Rejected`) when paused, or defer (`PolicyResult.Continue`) when unpaused.

### Policy Behavior

- **`run(...)`**
  - Returns `PolicyResult.Rejected` if `s_paused == true`.
  - Returns `PolicyResult.Continue` if `s_paused == false`.

### Example Use Cases

- **Emergency Stop**: Quickly block all sensitive functions in a contract during an emergency or maintenance window.
- **Maintenance Mode**: Temporarily pause interactions for upgrades or migrations.
- **Gradual Rollout**: Deploy paused, then activate when ready.

## RejectPolicy

### Overview

The `RejectPolicy` implements access control through a denylist. The policy immediately rejects the transaction if one of the supplied addresses is on the denylist, halting any subsequent policy checks.

### Specific Configuration

1. **Denylist Management**

   The contract [owner](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable.sol) can:

   - **`rejectAddress(address account)`**: Adds `account` to the denylist.
   - **`unrejectAddress(address account)`**: Removes `account` from the denylist.

2. **View Functions**
   - **`addressRejected(address account) -> bool`**: Returns `true` if `account` is on the denylist.

### Policy Parameters and Context

This policy expects a variable number of parameters, which are the addresses to check against the denylist. Each parameter
MUST be an address. If ANY of the addresses provided are present in the denylist, the transaction will be rejected.

### Policy Behavior

- **`run(...)`**

  - Returns `PolicyResult.Rejected` if any of the parameters is present on the denylist.
  - Returns `PolicyResult.Continue` otherwise

- **`postRun(...)`**
  - Not implemented (no state changes required)

### Example Use Cases

- **Account Blocking**:  Block malicious addresses, such as known hackers or compromised accounts.

## RoleBasedAccessControlPolicy

### Overview

The `RoleBasedAccessControlPolicy` utilize [OpenZeppelin's `AccessControlUpgradeable`](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/master/contracts/access/AccessControlUpgradeable.sol) to implement a flexible role-based access control system.

For example, to manage a transfer operation:

```solidity
bytes4 TRANSFER_SELECTOR = bytes4(keccak256("transfer(address,uint256)"));
bytes32 ADMIN_ROLE = keccak256("ADMIN_ROLE");

RoleBasedAccessControlPolicy policy = new RoleBasedAccessControlPolicy();

policy.grantRole(ADMIN_ROLE, bob);
policy.grantOperationAllowanceToRole(TRANSFER_SELECTOR, ADMIN_ROLE);
```

A transaction proceeds only if the sender holds a role that has been granted permission for the operation.

### Specific Configuration

1. **Role-Based Operation Allowance**

   - **`grantOperationAllowanceToRole(bytes4 operation, bytes32 role)`**: Adds a role to the list of roles that can perform the operation.
   - **`removeOperationAllowanceFromRole(bytes4 operation, bytes32 role)`**: Removes a role from that list.

2. **Account Role Management**

   - **`grantRole(bytes32 role, address account)`**: Assigns a role to a specific account.
   - **`revokeRole(bytes32 role, address account)`**: Revokes a role from an account.

3. **View Functions**
   - **`hasAllowedRole(bytes4 operation, address account) -> bool`**: Checks if the account has any of the roles that are allowed to perform the operation.
   - **`supportsInterface(bytes4 interfaceId) -> bool`**: Implements ERC165-style interface detection (inherited from `AccessControl` and `Policy`).

### Policy Parameters

| Parameter Name  | Type  | Description                                                                                                                            |
| --------------- | ----- | -------------------------------------------------------------------------------------------------------------------------------------- |
| _No parameters_ | _N/A_ | This policy does **not** require any parameters from the Policy Engine's configured Extractor and Mapper. It checks `sender` directly. |

No additional `context` is used or expected.

### Policy Behavior

- **`run(...)`**

  - Extracts the `operation (bytes4)` from the single parameter.
  - Checks whether the `sender` holds one of the roles with allowance for the `operation`.
  - If `hasAllowedRole` is `false`, returns `PolicyResult.Rejected`; otherwise, returns `PolicyResult.Continue`.

- **`postRun(...)`**
  - Not implemented in this policy (no state changes after `run`).

### Example Use Cases

- **Granular Function Permissions**: Each `operation` corresponds to a function selector. Certain roles can call only specific functions.
- **Decentralized Team Management**: Owner can quickly grant or revoke privileges to multiple operations across multiple roles.

## SecureMintPolicy

### Overview

The `SecureMintPolicy` ensures the total supply of a token does not exceed the actual reserves of the underlying asset. It retrieves reserves data from a Chainlink Proof of Reserve contract (or any contract compatible with the Data Feed interface) and compares it against the total supply of the token.

### Specific Configuration

1. **Reserves Feed**

   - **`setReservesFeed(address reservesFeed)`**: Updates the Chainlink data feed used for reserve validation.

2. **Reserve Margin**

   - **`enum ReserveMarginMode`**
      - `None`: No reserve margin. Policy will compare total supply against reserves directly.
      - `PositivePercentage`: Reserve margin is a positive percentage of the reserves, meaning total supply must be less than the reserves by a certain amount. e.g. If reserves = 1000 and margin = 10%, then total supply must be less than 900.
      - `PositiveAbsolute`: Reserve margin is a positive absolute value. e.g. If reserves = 1000 and margin = 50, then total supply must be less than 950.
      - `NegativePercentage`: Reserve margin is a negative percentage of the reserves, meaning total supply limit is greater than the reserves by a certain amount. e.g. If reserves = 1000 and margin = -10%, then total supply limit will be 1100.
      - `NegativeAbsolute`: Reserve margin is a negative absolute value. e.g. If reserves = 1000 and margin = -50, then total supply limit will be 1050.
   - **`setReserveMargin(ReserveMarginMode mode, uint256 amount)`**: Sets the reserve margin mode and amount. If the reserveMarginMode is percentage-based, amount will be interpreted as hundredths of a percent (e.g. 12.34% = 1234).

3. **Reserve Staleness**

   - **`setMaxStalenessSeconds(uint256 value)`**: Set the maximum staleness of the reserves data. Set to 0 to accept infinite staleness. If the data is older than this value, the policy will reject the transaction.

4. **View Functions**

   - **`reservesFeed() -> address`**: Returns the current reserves feed address.
   - **`maxStalenessSeconds() -> uint256`**: Returns the current maximum staleness value.
   - **`reserveMarginMode() -> ReserveMarginMode`**: Returns the current reserve margin mode.
   - **`reserveMarginAmount() -> uint256`**: Returns the current reserve margin amount.

### Policy Parameters

| Parameter Name | Type | Description |
| --- | --- | --- |
| `reservesFeed` | `address` | The address of the Chainlink Data Feed contract. |
| `reserveMarginMode` | `ReserveMarginMode` | The reserve margin mode. |
| `reserveMarginAmount` | `uint256` | The reserve margin amount. Interpreted as hundredths of a percent if `reserveMarginMode` is percentage-based. |
| `maxStalenessSeconds` | `uint256` | The maximum staleness of the reserves data. |

### Policy Behavior

- **`run(...)`**

   - Extracts the `amount (uint256)` from parameters.
   - Get latest reserves data from the reserves feed.
      - If `maxStalenessSeconds` is not 0 and the data is older than this value, return `PolicyResult.Rejected`.
   - Calculates the total backed supply of the token using the reserves value, `reserveMarginMode` and `reserveMarginAmount`.
      - If the total supply of the token is greater than the backed supply, returns `PolicyResult.Rejected`.
      - If the total supply of the token is less than or equal to the backed supply, returns `PolicyResult.Continue`.

- **`postRun(...)`**
  - Not implemented in this policy (no state changes after `run`).

### Example Use Cases
- **Collateralized Token Minting**: Ensure that the total supply of a token does not exceed the actual reserves of the underlying asset.

## VolumePolicy

#### Overview

The `VolumePolicy` enforces minimum and maximum value constraints. The policy compares a provided amount against configured bounds and rejects transactions that fall outside these limits.

For example, to limit transfers between 100 and 1000 tokens:

```solidity
VolumePolicy volumePolicy = new VolumePolicy();
volumePolicy.setMin(100);    // Minimum amount allowed
volumePolicy.setMax(1000);   // Maximum amount allowed (0 means no upper limit)
```

### Specific Configuration

1. **Minimum / Maximum Amount**

   - **`s_minAmount`**: The minimum allowed amount.
   - **`s_maxAmount`**: The maximum allowed amount (0 indicates no maximum limit).

2. **Owner Controls**

   The contract [owner](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable.sol) can:

   - **`setMin(uint256 minAmount)`**: Updates the minimum allowed amount. Must be strictly less than the current max (unless max is 0).
   - **`setMax(uint256 maxAmount)`**: Updates the maximum allowed amount. Must be strictly greater than the current min (unless min is 0).

3. **View Functions**
   - **`getMax() -> uint256`**: Returns the current maximum amount.
   - **`getMin() -> uint256`**: Returns the current minimum amount.

### Policy Parameters

The **VolumePolicy** expects **one** parameter in the `parameters` array:

| Parameter Name | Type      | Description                                                         |
| -------------- | --------- | ------------------------------------------------------------------- |
| `amount`       | `uint256` | The numeric value to check against `s_minAmount` and `s_maxAmount`. |

The policy expects no additional context.

### Policy Behavior

- **`run(...)`**

  - Validates parameter count equals 1
  - Decodes the parameter: `amount (uint256)`.
  - If `amount < s_minAmount` **or** `amount > s_maxAmount` (when `s_maxAmount != 0`), returns `PolicyResult.Rejected`.
  - Otherwise, returns `PolicyResult.Continue`.

- **`postRun(...)`**
  - Not used in this policy (no state changes after `run`).

### Example Use Cases

- **Purchase Limits**: Restrict transaction amounts to a certain range.
- **Rate Controls**: Ensure that any single transaction doesn’t fall below a minimum or exceed a maximum allowed value.
- **Resource/Token-Transfer Rules**: Protect a system from extremely small or large transfers that could be disruptive.

## VolumeRatePolicy

### Overview

The `VolumeRatePolicy` enforces per-account volume limits within configurable time periods. The policy tracks cumulative amounts and rejects transactions that would exceed the maximum allowed volume in the current period.

For example, to limit transfers to 1000 tokens per hour:

```solidity
// Create policy with 1-hour period and 1000 token limit
VolumeRatePolicy policy = new VolumeRatePolicy(
    3600,     // Time period (1 hour in seconds)
    1000      // Max amount per period
);
```

### Specific Configuration

1. **Time Period (`s_timePeriod`)**

   - The duration (in seconds) of a repeating window (e.g., 3600 for hourly).

2. **Max Amount (`s_maxAmount`)**

   - The upper bound on total volume permitted per account in each time period.
   - If a transaction plus the existing volume in the current time period exceeds this limit, the policy rejects the transaction.

3. **Owner Controls**
   The contract [owner](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable.sol) can:

   - **`setMaxAmount(uint256 _maxAmount)`**: Updates the maximum volume limit.
   - **`setTimePeriod(uint256 _timePeriod)`**: Updates the time period length in seconds.
   - **`getMaxAmount()`** / **`getTimePeriod()`**: View functions for the current configuration.

### Policy Parameters

The **VolumeRatePolicy** expects exactly **two** parameters in the `parameters` array, in this order:

| Parameter Name | Type      | Description                                  |
| -------------- | --------- | -------------------------------------------- |
| `amount`       | `uint256` | The amount being transferred.                |
| `account`      | `address` | The address for which the volume is tracked. |

No additional `context` is used.

### Policy Behavior

1. **`run(...)`**

   - Validates parameter count equals 2.
   - Derives the current time period (`currentPeriod = block.timestamp / s_timePeriod`).
   - Compares the stored `timePeriod` and `amount` for `account` against the `currentPeriod` and the incoming `amount`.
   - If the current period matches, checks whether `existingVolume + newAmount` exceeds `s_maxAmount`. If so, returns `PolicyResult.Rejected`; else, `PolicyResult.Continue`.
   - If the period is new for this account and `newAmount` exceeds `s_maxAmount`, returns `PolicyResult.Rejected`; otherwise, `PolicyResult.Continue`.

2. **`postRun(...)`**
   - If the transaction wasn’t rejected, updates the stored record for that account in the current time period by adding `amount`.
   - If this is a new period, the policy resets the stored amount to `amount`.

### Example Use Cases

- **Rate Limiting**: Enforce maximum transfer amounts per hour/day
- **Usage Quotas**: Prevent resource exhaustion by single accounts
- **Compliance**: Implement regulatory transfer limits per time window
