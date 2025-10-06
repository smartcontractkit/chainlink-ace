// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

/**
 * @title ICredentialDataValidator
 * @dev Interface for validating the data associated with a credential.
 */
interface ICredentialDataValidator {
  /**
   * @notice Validates the data associated with a credential assignment.
   * @dev This function MUST NOT revert. Handle all validation failures gracefully and return
   * false instead of allowing exceptions to propagate.
   * @param ccid The cross-chain identity of the account.
   * @param account The account to validate.
   * @param credentialTypeId The credential type identifier to validate.
   * @param credentialData The data associated with the credential.
   * @param context Additional information or authorization to perform the operation.
   * @return True if the credential is valid, false otherwise.
   */
  function validateCredentialData(
    bytes32 ccid,
    address account,
    bytes32 credentialTypeId,
    bytes calldata credentialData,
    bytes calldata context
  )
    external
    view
    returns (bool);
}
