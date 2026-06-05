// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IExtractor} from "../interfaces/IExtractor.sol";
import {IPolicyEngine} from "../interfaces/IPolicyEngine.sol";
import {ICredentialRegistry} from "../../../cross-chain-identity/src/interfaces/ICredentialRegistry.sol";

/**
 * @title CredentialRegistryExtractor
 * @notice Extracts parameters from ICredentialRegistry administrative function calls.
 * @dev Supports registerCredential, registerCredentials, removeCredential, and renewCredential.
 *      For registerCredentials (batch), credentialTypeId is zero since the input is an array.
 *      For removeCredential, expiresAt is zero since the function does not take an expiry.
 */
contract CredentialRegistryExtractor is IExtractor {
  /// @notice Type and version of the extractor
  string public constant override typeAndVersion = "CredentialRegistryExtractor 1.1.1";

  /// @notice Parameter key for the cross-chain identity
  bytes32 public constant PARAM_CCID = keccak256("ccid");

  /// @notice Parameter key for the credential type identifier
  bytes32 public constant PARAM_CREDENTIAL_TYPE_ID = keccak256("credentialTypeId");

  /// @notice Parameter key for the credential type identifiers (batch operations)
  bytes32 public constant PARAM_CREDENTIAL_TYPE_IDS = keccak256("credentialTypeIds");

  /// @notice Parameter key for the credential expiration timestamp
  bytes32 public constant PARAM_EXPIRES_AT = keccak256("expiresAt");

  /**
   * @inheritdoc IExtractor
   * @dev Extracts ccid, credentialTypeId, and expiresAt from ICredentialRegistry admin calls.
   *      - registerCredential(bytes32,bytes32,uint40,bytes,bytes): all three params decoded
   *      - registerCredentials(bytes32,bytes32[],uint40,bytes[],bytes): all three params decoded
   *        (^ note credentialTypeIds is decoded as a list of ids)
   *      - removeCredential(bytes32,bytes32,bytes): ccid and credentialTypeId decoded
   *      - renewCredential(bytes32,bytes32,uint40,bytes): all three params decoded
   */
  function extract(IPolicyEngine.Payload calldata payload)
    external
    pure
    override
    returns (IPolicyEngine.Parameter[] memory)
  {
    if (payload.selector == ICredentialRegistry.registerCredential.selector) {
      (bytes32 ccid, bytes32 credentialTypeId, uint40 expiresAt,,) =
        abi.decode(payload.data, (bytes32, bytes32, uint40, bytes, bytes));
      IPolicyEngine.Parameter[] memory result = new IPolicyEngine.Parameter[](3);
      result[0] = IPolicyEngine.Parameter(PARAM_CCID, abi.encode(ccid));
      result[1] = IPolicyEngine.Parameter(PARAM_CREDENTIAL_TYPE_ID, abi.encode(credentialTypeId));
      result[2] = IPolicyEngine.Parameter(PARAM_EXPIRES_AT, abi.encode(expiresAt));
      return result;
    } else if (payload.selector == ICredentialRegistry.removeCredential.selector) {
      (bytes32 ccid, bytes32 credentialTypeId,) = abi.decode(payload.data, (bytes32, bytes32, bytes));
      IPolicyEngine.Parameter[] memory result = new IPolicyEngine.Parameter[](2);
      result[0] = IPolicyEngine.Parameter(PARAM_CCID, abi.encode(ccid));
      result[1] = IPolicyEngine.Parameter(PARAM_CREDENTIAL_TYPE_ID, abi.encode(credentialTypeId));
      return result;
    } else if (payload.selector == ICredentialRegistry.renewCredential.selector) {
      (bytes32 ccid, bytes32 credentialTypeId, uint40 expiresAt,) =
        abi.decode(payload.data, (bytes32, bytes32, uint40, bytes));
      IPolicyEngine.Parameter[] memory result = new IPolicyEngine.Parameter[](3);
      result[0] = IPolicyEngine.Parameter(PARAM_CCID, abi.encode(ccid));
      result[1] = IPolicyEngine.Parameter(PARAM_CREDENTIAL_TYPE_ID, abi.encode(credentialTypeId));
      result[2] = IPolicyEngine.Parameter(PARAM_EXPIRES_AT, abi.encode(expiresAt));
      return result;
    } else if (payload.selector == ICredentialRegistry.registerCredentials.selector) {
      (bytes32 ccid, bytes32[] memory credentialTypeIds, uint40 expiresAt,,) =
        abi.decode(payload.data, (bytes32, bytes32[], uint40, bytes[], bytes));
      IPolicyEngine.Parameter[] memory result = new IPolicyEngine.Parameter[](3);
      result[0] = IPolicyEngine.Parameter(PARAM_CCID, abi.encode(ccid));
      result[1] = IPolicyEngine.Parameter(PARAM_CREDENTIAL_TYPE_IDS, abi.encode(credentialTypeIds));
      result[2] = IPolicyEngine.Parameter(PARAM_EXPIRES_AT, abi.encode(expiresAt));
      return result;
    } else {
      revert IPolicyEngine.UnsupportedSelector(payload.selector);
    }
  }
}
