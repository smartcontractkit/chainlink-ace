// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

/**
 * @title ICredentialValidator
 * @dev Interface for validating a ccid has a credential.
 */
interface ICredentialValidator {
  /**
   * @notice Checks if a credential is valid for the specified cross-chain identity.
   * @dev This function MUST NOT revert. Handle all validation failures gracefully and return
   * false instead of allowing exceptions to propagate.
   * @param ccid The cross-chain identity of the account.
   * @param credentialTypeId The credential type identifier.
   * @param context Additional information or authorization to perform the operation.
   * @return True if the credential is valid, otherwise false.
   */
  function validate(bytes32 ccid, bytes32 credentialTypeId, bytes calldata context) external view returns (bool);

  /**
   * @notice Checks if all of the credentials are valid for the specified cross-chain identity.
   * @dev This function MUST NOT revert. Handle all validation failures gracefully and return
   * false instead of allowing exceptions to propagate.
   * @param ccid The cross-chain identity of the account.
   * @param credentialTypeIds The credential type identifiers.
   * @param context Additional information or authorization to perform the operation.
   * @return True if the credential is valid, otherwise false.
   */
  function validateAll(
    bytes32 ccid,
    bytes32[] calldata credentialTypeIds,
    bytes calldata context
  )
    external
    view
    returns (bool);
}
