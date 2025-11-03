// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

/**
 * @title IIdentityRegistry
 * @notice The interface for managing identities within a registry. Identities are a bytes32 identifier known as
 * the Cross-Chain ID (CCID), in which credentials and other information can be associated with. Multiple local
 * blockchain accounts can be associated with a single CCID, but each account can only be associated with one CCID
 * within this registry.
 */
interface IIdentityRegistry {
  /// @notice Error emitted when an identity is already registered.
  error IdentityAlreadyRegistered(bytes32 ccid, address account);
  /// @notice Error emitted when an identity is not found.
  error IdentityNotFound(bytes32 ccid, address account);
  /// @notice Error emitted when an invalid identity configuration was attempted.
  error InvalidIdentityConfiguration(bytes errorReason);

  /**
   * @notice Emitted when a new identity is registered.
   * @param ccid The common cross-chain identifier of the identity.
   * @param account The address of the account on this chain.
   */
  event IdentityRegistered(bytes32 indexed ccid, address indexed account);

  /**
   * @notice Emitted when an identity is removed.
   * @param ccid The common cross-chain identifier of the identity.
   * @param account The address of the account on this chain.
   */
  event IdentityRemoved(bytes32 indexed ccid, address indexed account);

  /**
   * @notice Registers a new local account address for a cross-chain identity.
   *
   * - MUST be access controlled to prevent unauthorized identity registration.
   * - MUST revert with `IdentityAlreadyRegistered` if the ccid/account pair is already registered.
   * - MUST emit the `IdentityRegistered` event.
   *
   * @param ccid The common cross-chain identifier of the identity.
   * @param account The address of the account on this chain.
   * @param context Additional information or authorization to perform the operation.
   */
  function registerIdentity(bytes32 ccid, address account, bytes calldata context) external;

  /**
   * @notice Registers a list of new ccid/local account address pairs.
   *
   * - MUST be access controlled to prevent unauthorized identity registration.
   * - MUST revert with `IdentityAlreadyRegistered` if one of the ccid/account pairs is already registered.
   * - MUST emit the `IdentityRegistered` event for each ccid/account pair.
   *
   * @param ccids The list of common cross-chain identifiers for the identities.
   * @param accounts The list of address for the identities on this chain.
   * @param context Additional information or authorization to perform the operation.
   */
  function registerIdentities(bytes32[] calldata ccids, address[] calldata accounts, bytes calldata context) external;

  /**
   * @notice Removes an identity.
   *
   * - MUST be access controlled to prevent unauthorized identity removal.
   * - MUST revert with `IdentityNotFound` if the ccid/account pair is not registered.
   * - MUST emit the `IdentityRemoved` event.
   *
   * @param ccid The common cross-chain identifier of the identity.
   * @param account The address of the account on this chain.
   * @param context Additional information or authorization to perform the operation.
   */
  function removeIdentity(bytes32 ccid, address account, bytes calldata context) external;

  /**
   * @notice Gets the common cross-chain identifier of an identity.
   * @param account The address of the account on this chain.
   * @return the common cross-chain identifier of the identity.
   */
  function getIdentity(address account) external view returns (bytes32);

  /**
   * @notice Gets the addresses of an account on this chain.
   * @param ccid The common cross-chain identifier of the identity.
   * @return the addresses of the accounts on this chain.
   */
  function getAccounts(bytes32 ccid) external view returns (address[] memory);
}
