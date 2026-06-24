// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IExtractor} from "../interfaces/IExtractor.sol";
import {IPolicyEngine} from "../interfaces/IPolicyEngine.sol";
import {IIdentityRegistry} from "../../../cross-chain-identity/src/interfaces/IIdentityRegistry.sol";

/**
 * @title IdentityRegistryExtractor
 * @notice Extracts parameters from IIdentityRegistry administrative function calls.
 * @dev Supports registerIdentity, registerIdentities, and removeIdentity.
 *      For registerIdentity and removeIdentity, returns PARAM_CCID and PARAM_ACCOUNT.
 *      For registerIdentities (batch), returns PARAM_CCIDS and PARAM_ACCOUNTS.
 */
contract IdentityRegistryExtractor is IExtractor {
  /// @notice Type and version of the extractor
  string public constant override typeAndVersion = "IdentityRegistryExtractor 1.1.1";

  /// @notice Parameter key for the cross-chain identity
  bytes32 public constant PARAM_CCID = keccak256("ccid");

  /// @notice Parameter key for the local account address
  bytes32 public constant PARAM_ACCOUNT = keccak256("account");

  /// @notice Parameter key for the cross-chain identities array (batch operations)
  bytes32 public constant PARAM_CCIDS = keccak256("ccids");

  /// @notice Parameter key for the local account addresses array (batch operations)
  bytes32 public constant PARAM_ACCOUNTS = keccak256("accounts");

  /**
   * @inheritdoc IExtractor
   * @dev Extracts parameters from IIdentityRegistry admin calls.
   *      - registerIdentity(bytes32,address,bytes): returns [PARAM_CCID, PARAM_ACCOUNT]
   *      - registerIdentities(bytes32[],address[],bytes): returns [PARAM_CCIDS, PARAM_ACCOUNTS]
   *      - removeIdentity(bytes32,address,bytes): returns [PARAM_CCID, PARAM_ACCOUNT]
   */
  function extract(IPolicyEngine.Payload calldata payload)
    external
    pure
    override
    returns (IPolicyEngine.Parameter[] memory)
  {
    if (
      payload.selector == IIdentityRegistry.registerIdentity.selector
        || payload.selector == IIdentityRegistry.removeIdentity.selector
    ) {
      (bytes32 ccid, address account,) = abi.decode(payload.data, (bytes32, address, bytes));
      IPolicyEngine.Parameter[] memory result = new IPolicyEngine.Parameter[](2);
      result[0] = IPolicyEngine.Parameter(PARAM_CCID, abi.encode(ccid));
      result[1] = IPolicyEngine.Parameter(PARAM_ACCOUNT, abi.encode(account));
      return result;
    } else if (payload.selector == IIdentityRegistry.registerIdentities.selector) {
      (bytes32[] memory ccids, address[] memory accounts,) = abi.decode(payload.data, (bytes32[], address[], bytes));
      IPolicyEngine.Parameter[] memory result = new IPolicyEngine.Parameter[](2);
      result[0] = IPolicyEngine.Parameter(PARAM_CCIDS, abi.encode(ccids));
      result[1] = IPolicyEngine.Parameter(PARAM_ACCOUNTS, abi.encode(accounts));
      return result;
    } else {
      revert IPolicyEngine.UnsupportedSelector(payload.selector);
    }
  }
}
