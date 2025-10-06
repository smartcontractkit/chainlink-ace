// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IExtractor} from "@chainlink/policy-management/interfaces/IExtractor.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {ComplianceTokenERC20} from "../../../tokens/erc-20/src/ComplianceTokenERC20.sol";

/**
 * @title ComplianceTokenFreezeUnfreezeExtractor
 * @notice Extracts parameters from Compliance Token ERC20 freeze and unfreeze function calls.
 * @dev This extractor supports freeze() and unfreeze() function selectors from the ComplianceTokenERC20 contract
 *      and extracts the target account address and amount parameters for compliance-related freezing operations.
 */
contract ComplianceTokenFreezeUnfreezeExtractor is IExtractor {
  /// @notice Parameter key for the target account address in freeze/unfreeze operations
  bytes32 public constant PARAM_ACCOUNT = keccak256("account");

  /// @notice Parameter key for the amount being frozen or unfrozen
  bytes32 public constant PARAM_AMOUNT = keccak256("amount");

  /**
   * @notice Extracts parameters from ComplianceTokenERC20 freeze and unfreeze function calls.
   * @dev Supports freeze(address account, uint256 amount) and unfreeze(address account, uint256 amount) functions.
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

    // Both freeze and unfreeze functions take identical parameters: (address account, uint256 amount)
    if (
      payload.selector == ComplianceTokenERC20.freeze.selector
        || payload.selector == ComplianceTokenERC20.unfreeze.selector
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
