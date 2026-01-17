// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IExtractor} from "@chainlink/policy-management/interfaces/IExtractor.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {ComplianceTokenERC7943} from "../../../tokens/erc-7943/src/ComplianceTokenERC7943.sol";

/**
 * @title ERC7943WhitelistExtractor
 * @notice Extracts parameters from ERC-7943 Compliance Token whitelist change function calls.
 * @dev This extractor supports the changeWhitelist() function selector from the ComplianceTokenERC7943
 *      contract and extracts the account address and status parameters for whitelist operations.
 */
contract ERC7943WhitelistExtractor is IExtractor {
  /// @notice Parameter key for the target account address in whitelist operations
  bytes32 public constant PARAM_ACCOUNT = keccak256("account");

  /// @notice Parameter key for the whitelist status (true/false)
  bytes32 public constant PARAM_STATUS = keccak256("status");

  /**
   * @notice Extracts parameters from ComplianceTokenERC7943 changeWhitelist function calls.
   * @dev Supports changeWhitelist(address account, bool status) function.
   * @param payload The policy engine payload containing the function selector and calldata
   * @return An array of two parameters: PARAM_ACCOUNT and PARAM_STATUS
   */
  function extract(IPolicyEngine.Payload calldata payload)
    external
    pure
    override
    returns (IPolicyEngine.Parameter[] memory)
  {
    address account = address(0);
    bool status = false;

    if (payload.selector == ComplianceTokenERC7943.changeWhitelist.selector) {
      (account, status) = abi.decode(payload.data, (address, bool));
    } else {
      revert IPolicyEngine.UnsupportedSelector(payload.selector);
    }

    // Build the parameter array with extracted values
    IPolicyEngine.Parameter[] memory result = new IPolicyEngine.Parameter[](2);
    result[0] = IPolicyEngine.Parameter(PARAM_ACCOUNT, abi.encode(account));
    result[1] = IPolicyEngine.Parameter(PARAM_STATUS, abi.encode(status));

    return result;
  }
}
