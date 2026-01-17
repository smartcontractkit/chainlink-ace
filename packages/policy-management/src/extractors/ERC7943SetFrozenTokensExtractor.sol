// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IExtractor} from "@chainlink/policy-management/interfaces/IExtractor.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {IERC7943Fungible} from "../../../tokens/erc-7943/src/interfaces/IERC7943.sol";

/**
 * @title ERC7943SetFrozenTokensExtractor
 * @notice Extracts parameters from ERC-7943 token setFrozenTokens function calls.
 * @dev This extractor supports the setFrozenTokens() function selector from the ERC-7943 token standard
 *      and extracts the account address and amount parameters for freezing operations.
 */
contract ERC7943SetFrozenTokensExtractor is IExtractor {
  /// @notice Parameter key for the target account address in freeze operations
  bytes32 public constant PARAM_ACCOUNT = keccak256("account");

  /// @notice Parameter key for the amount being frozen
  bytes32 public constant PARAM_AMOUNT = keccak256("amount");

  /**
   * @notice Extracts parameters from ERC7943 setFrozenTokens function calls.
   * @dev Supports setFrozenTokens(address account, uint256 amount) function.
   * @param payload The policy engine payload containing the function selector and calldata
   * @return An array of two parameters: PARAM_ACCOUNT and PARAM_AMOUNT
   */
  function extract(IPolicyEngine.Payload calldata payload)
    external
    pure
    override
    returns (IPolicyEngine.Parameter[] memory)
  {
    address account = address(0);
    uint256 amount = 0;

    if (payload.selector == IERC7943Fungible.setFrozenTokens.selector) {
      (account, amount) = abi.decode(payload.data, (address, uint256));
    } else {
      revert IPolicyEngine.UnsupportedSelector(payload.selector);
    }

    // Build the parameter array with extracted values
    IPolicyEngine.Parameter[] memory result = new IPolicyEngine.Parameter[](2);
    result[0] = IPolicyEngine.Parameter(PARAM_ACCOUNT, abi.encode(account));
    result[1] = IPolicyEngine.Parameter(PARAM_AMOUNT, abi.encode(amount));

    return result;
  }
}
