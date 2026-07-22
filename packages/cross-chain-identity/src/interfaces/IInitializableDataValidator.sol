// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

/**
 * @title IInitializableDataValidator
 * @notice Minimal initializer surface for data validator clones and proxies.
 * @dev Implementations decode `configData` according to their own schema; factories must document the encoding.
 */
interface IInitializableDataValidator {
  /**
   * @notice Initializes the validator (typically immediately after clone or proxy deployment).
   * @param initialOwner The address that will own the validator.
   * @param configData ABI-encoded implementation-specific configuration (see implementation NatSpec).
   */
  function initialize(address initialOwner, bytes calldata configData) external;
}
