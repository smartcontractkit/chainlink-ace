// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IExtractor} from "@chainlink/policy-management/interfaces/IExtractor.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {IToken} from "../../../vendor/erc-3643/token/IToken.sol";

/**
 * @title ERC3643FreezeUnfreezeExtractor
 * @notice Extracts parameters from ERC3643 token partial freeze and unfreeze function calls.
 * @dev This extractor supports freezePartialTokens() and unfreezePartialTokens() function selectors
 *      from the ERC3643 token standard and extracts the target account address and amount parameters.
 */
contract ERC3643FreezeUnfreezeExtractor is IExtractor {
  /// @notice Parameter key for the target account address in freeze/unfreeze operations
  bytes32 public constant PARAM_ACCOUNT = keccak256("account");

  /// @notice Parameter key for the amount being frozen or unfrozen
  bytes32 public constant PARAM_AMOUNT = keccak256("amount");

  /**
   * @notice Extracts parameters from ERC3643 partial freeze and unfreeze function calls.
   * @dev Supports freezePartialTokens(address account, uint256 amount) and
   *      unfreezePartialTokens(address account, uint256 amount) functions.
   *      Both functions have identical parameter structures.
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

    // Both freeze and unfreeze functions have the same signature: (address account, uint256 amount)
    if (
      payload.selector == IToken.freezePartialTokens.selector
        || payload.selector == IToken.unfreezePartialTokens.selector
    ) {
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
