// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {ICredentialRegistry} from "../../src/interfaces/ICredentialRegistry.sol";

/**
 * @title MockCredentialRegistryReverting
 * @notice Mock credential registry that can be configured to revert on validate() calls
 * @dev Used for testing error handling in CredentialRegistryIdentityValidator
 */
contract MockCredentialRegistryReverting is ICredentialRegistry {
  bool private s_shouldRevert;
  string private s_revertMessage;

  function setShouldRevert(bool shouldRevert) public {
    s_shouldRevert = shouldRevert;
  }

  function setRevertMessage(string memory message) public {
    s_revertMessage = message;
  }

  function validate(
    bytes32, /*ccid*/
    bytes32, /*credentialTypeId*/
    bytes calldata /*context*/
  )
    external
    view
    returns (bool)
  {
    if (s_shouldRevert) {
      revert(s_revertMessage);
    }
    return false; // Default behavior when not reverting
  }

  // Minimal implementation of required interface methods
  function registerCredential(
    bytes32, /*ccid*/
    bytes32, /*credentialTypeId*/
    uint40, /*expiresAt*/
    bytes calldata, /*credentialData*/
    bytes calldata /*context*/
  )
    external
  {
    revert("Not implemented");
  }

  function registerCredentials(
    bytes32, /*ccid*/
    bytes32[] calldata, /*credentialTypeIds*/
    uint40, /*expiresAt*/
    bytes[] calldata, /*credentialDatas*/
    bytes calldata /*context*/
  )
    external
  {
    revert("Not implemented");
  }

  function renewCredential(
    bytes32, /*ccid*/
    bytes32, /*credentialTypeId*/
    uint40, /*expiresAt*/
    bytes calldata /*context*/
  )
    external
  {
    revert("Not implemented");
  }

  function revokeCredential(bytes32, /*ccid*/ bytes32, /*credentialTypeId*/ bytes calldata /*context*/ ) external {
    revert("Not implemented");
  }

  function removeCredential(bytes32, /*ccid*/ bytes32, /*credentialTypeId*/ bytes calldata /*context*/ ) external {
    revert("Not implemented");
  }

  function getCredential(
    bytes32, /*ccid*/
    bytes32 /*credentialTypeId*/
  )
    external
    view
    returns (ICredentialRegistry.Credential memory)
  {
    revert("Not implemented");
  }

  function getCredentials(
    bytes32, /*ccid*/
    bytes32[] calldata /*credentialTypeIds*/
  )
    external
    view
    returns (ICredentialRegistry.Credential[] memory)
  {
    revert("Not implemented");
  }

  function getCredentialTypes(bytes32 /*ccid*/ ) external view returns (bytes32[] memory) {
    revert("Not implemented");
  }

  function hasCredential(bytes32, /*ccid*/ bytes32 /*credentialTypeId*/ ) external view returns (bool) {
    revert("Not implemented");
  }

  function isCredentialExpired(bytes32, /*ccid*/ bytes32 /*credentialTypeId*/ ) external view returns (bool) {
    revert("Not implemented");
  }

  function validateAll(
    bytes32, /*ccid*/
    bytes32[] calldata, /*credentialTypeIds*/
    bytes calldata /*context*/
  )
    external
    view
    returns (bool)
  {
    revert("Not implemented");
  }

  function supportsInterface(bytes4 /*interfaceId*/ ) external pure returns (bool) {
    return true;
  }
}
