// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IExtractor} from "@chainlink/policy-management/interfaces/IExtractor.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {ComplianceTokenERC7943} from "../../../tokens/erc-7943/src/ComplianceTokenERC7943.sol";

/**
 * @title ERC7943WhitelistExtractor
 * @notice Extracts parameters from ERC-7943 Compliance Token whitelist change function calls.
 * @dev This extractor supports the changeWhitelist() function selector from the ComplianceTokenERC7943
 *      contract and extracts the account address and the send/receive eligibility parameters.
 */
contract ERC7943WhitelistExtractor is IExtractor {
  /// @notice Type and version of the extractor
  string public constant override typeAndVersion = "ERC7943WhitelistExtractor 1.0.0";

  /// @notice Parameter key for the target account address in whitelist operations
  bytes32 public constant PARAM_ACCOUNT = keccak256("account");

  /// @notice Parameter key for the send-eligibility status (true/false)
  bytes32 public constant PARAM_SEND_ALLOWED = keccak256("sendAllowed");

  /// @notice Parameter key for the receive-eligibility status (true/false)
  bytes32 public constant PARAM_RECEIVE_ALLOWED = keccak256("receiveAllowed");

  /**
   * @notice Extracts parameters from ComplianceTokenERC7943 changeWhitelist function calls.
   * @dev Supports changeWhitelist(address account, bool sendAllowed, bool receiveAllowed) function.
   * @param payload The policy engine payload containing the function selector and calldata
   * @return An array of three parameters: PARAM_ACCOUNT, PARAM_SEND_ALLOWED and PARAM_RECEIVE_ALLOWED
   */
  function extract(IPolicyEngine.Payload calldata payload)
    external
    pure
    override
    returns (IPolicyEngine.Parameter[] memory)
  {
    address account = address(0);
    bool sendAllowed = false;
    bool receiveAllowed = false;

    if (payload.selector == ComplianceTokenERC7943.changeWhitelist.selector) {
      (account, sendAllowed, receiveAllowed) = abi.decode(payload.data, (address, bool, bool));
    } else {
      revert IPolicyEngine.UnsupportedSelector(payload.selector);
    }

    // Build the parameter array with extracted values
    IPolicyEngine.Parameter[] memory result = new IPolicyEngine.Parameter[](3);
    result[0] = IPolicyEngine.Parameter(PARAM_ACCOUNT, abi.encode(account));
    result[1] = IPolicyEngine.Parameter(PARAM_SEND_ALLOWED, abi.encode(sendAllowed));
    result[2] = IPolicyEngine.Parameter(PARAM_RECEIVE_ALLOWED, abi.encode(receiveAllowed));

    return result;
  }
}
