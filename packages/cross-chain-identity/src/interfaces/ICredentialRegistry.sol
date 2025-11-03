// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {ICredentialValidator} from "./ICredentialValidator.sol";

/**
 * @title ICredentialRegistry
 * @dev Interface for managing the credential registry.
 */
interface ICredentialRegistry is ICredentialValidator {
  /// @notice Error emitted when a credential type identifier is already registered to the ccid.
  error CredentialAlreadyRegistered(bytes32 ccid, bytes32 credentialTypeId);
  /// @notice Error emitted when a credential type identifier is not found to be associated to the ccid.
  error CredentialNotFound(bytes32 ccid, bytes32 credentialTypeId);
  /// @notice Error emitted when an invalid credential configuration was attempted.
  error InvalidCredentialConfiguration(string errorReason);

  /**
   * @dev The struct for a credential. A credential is a piece of arbitrary data that is associated with a credential
   * type identifier, and optionally has an expiration time. The data can be anything that is relevant to the credential
   * type.
   * The ICredentialRegistry maps a cross-chain identifier (CCID) to one or more credentials, managing their lifecycle.
   */
  struct Credential {
    uint40 expiresAt;
    bytes credentialData;
  }

  /**
   * @notice Emitted when a credential is registered.
   * @param ccid The cross-chain identity of the account.
   * @param credentialTypeId The credential type identifier that was registered.
   * @param expiresAt The expiration time of the credential.
   * @param credentialData The data associated with the credential.
   */
  event CredentialRegistered(
    bytes32 indexed ccid, bytes32 indexed credentialTypeId, uint40 expiresAt, bytes credentialData
  );

  /**
   * @notice Emitted when a credential is removed.
   * @param ccid The cross-chain identity of the account.
   * @param credentialTypeId The credential type identifier that was removed.
   */
  event CredentialRemoved(bytes32 indexed ccid, bytes32 indexed credentialTypeId);

  /**
   * @notice Emitted when a credential is renewed.
   * @param ccid The cross-chain identity of the account.
   * @param credentialTypeId The credential type identifier that was renewed.
   * @param previousExpiresAt The previous expiration time of the credential.
   * @param expiresAt The new expiration time of the credential.
   */
  event CredentialRenewed(
    bytes32 indexed ccid, bytes32 indexed credentialTypeId, uint40 previousExpiresAt, uint40 expiresAt
  );

  /**
   * @notice Registers a credential for an account.
   *
   * - MUST revert with `CredentialAlreadyRegistered` if the credential is already registered.
   * - MUST emit the `CredentialRegistered` event.
   *
   * @param ccid The cross-chain identity of the account.
   * @param credentialTypeId The credential type identifier to associate with the account.
   * @param expiresAt The expiration time (MUST be a future timestamp) of the credential, 0 for no expiration.
   * @param credentialData The data associated with the credential.
   * @param context Additional information or authorization to perform the operation.
   */
  function registerCredential(
    bytes32 ccid,
    bytes32 credentialTypeId,
    uint40 expiresAt,
    bytes calldata credentialData,
    bytes calldata context
  )
    external;

  /**
   * @notice Registers a list of credentials for an account.
   *
   * - MUST revert with `CredentialAlreadyRegistered` if one of the credentials is already registered.
   * - MUST emit the `CredentialRegistered` event for each credential.
   *
   * @param ccid The cross-chain identity of the account.
   * @param credentialTypeIds The credential type identifiers to associate with the account.
   * @param expiresAt The expiration time (MUST be a future timestamp) of the credential, 0 for no expiration.
   * @param credentialDatas The list of data associated with each credential.
   * @param context Additional information or authorization to perform the operation.
   */
  function registerCredentials(
    bytes32 ccid,
    bytes32[] calldata credentialTypeIds,
    uint40 expiresAt,
    bytes[] calldata credentialDatas,
    bytes calldata context
  )
    external;

  /**
   * @notice Removes a credential from an account.
   *
   * - MUST revert with `CredentialNotFound` if the credential is not found.
   * - MUST emit the `CredentialRemoved` event.
   *
   * @param ccid The cross-chain identity of the account.
   * @param credentialTypeId The credential type identifier to remove from the account.
   * @param context Additional information or authorization to perform the operation.
   */
  function removeCredential(bytes32 ccid, bytes32 credentialTypeId, bytes calldata context) external;

  /**
   * @notice Renews the expiration time of a credential.
   *
   * - MUST revert with `CredentialNotFound` if the credential is not found.
   * - MUST emit the `CredentialRenewed` event.
   *
   * @param ccid The cross-chain identity of the account.
   * @param credentialTypeId The credential type identifier to renew.
   * @param expiresAt The updated expiration time (MUST be a future timestamp) of the credential, 0 for no expiration.
   * @param context Additional information or authorization to perform the operation.
   */
  function renewCredential(bytes32 ccid, bytes32 credentialTypeId, uint40 expiresAt, bytes calldata context) external;

  /**
   * @notice Checks if a credential is expired.
   * @param ccid The cross-chain identity of the account.
   * @param credentialTypeId The credential type identifier.
   * @return True if the credential is expired, false otherwise.
   */
  function isCredentialExpired(bytes32 ccid, bytes32 credentialTypeId) external view returns (bool);

  /**
   * @notice Gets all of the credential types associated with an account, expired or not.
   * @param ccid The cross-chain identity of the account.
   * @return The credential type identifiers associated with the account.
   */
  function getCredentialTypes(bytes32 ccid) external view returns (bytes32[] memory);

  /**
   * @notice Retrieves a credential associated with a given account and credential type.
   * - MUST revert with `CredentialNotFound` if the credential does not exist for the given `ccid` and
   * `credentialTypeId`.
   *
   * @param ccid The cross-chain identity of the account.
   * @param credentialTypeId The credential type identifier to fetch.
   * @return A `Credential` struct containing:
   *         - `expiresAt`: The expiration time of the credential (0 if no expiration).
   *         - `credentialData`: The arbitrary data associated with the credential.
   */
  function getCredential(bytes32 ccid, bytes32 credentialTypeId) external view returns (Credential memory);

  /**
   * @notice Retrieves multiple credentials associated with a given account and a list of credential types.
   * - MUST revert with `CredentialNotFound` if any of the requested credentials do not exist for the given `ccid`.
   *
   * @param ccid The cross-chain identity of the account.
   * @param credentialTypeIds The list of credential type identifiers to fetch.
   * @return An array of `Credential` structs, each containing:
   *         - `expiresAt`: The expiration time of the credential (0 if no expiration).
   *         - `credentialData`: The arbitrary data associated with the credential.
   */
  function getCredentials(
    bytes32 ccid,
    bytes32[] calldata credentialTypeIds
  )
    external
    view
    returns (Credential[] memory);
}
