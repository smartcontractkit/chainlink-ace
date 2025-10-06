// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IExtractor} from "@chainlink/policy-management/interfaces/IExtractor.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {IToken} from "../../../vendor/erc-3643/token/IToken.sol";

/**
 * @title ERC3643MintBurnExtractor
 * @notice Extracts parameters from ERC3643 token mint and burn function calls.
 * @dev This extractor supports both mint() and burn() function selectors from the ERC3643 token standard
 *      and extracts the target account address and amount parameters from the function calldata.
 */
contract ERC3643MintBurnExtractor is IExtractor {
  /// @notice Parameter key for the target account address in mint/burn operations
  bytes32 public constant PARAM_ACCOUNT = keccak256("account");

  /// @notice Parameter key for the amount being minted or burned
  bytes32 public constant PARAM_AMOUNT = keccak256("amount");

  /**
   * @notice Extracts parameters from ERC3643 mint and burn function calls.
   * @dev Supports mint(address account, uint256 amount) and burn(address account, uint256 amount) functions.
   *      Both functions have identical parameter structures, so they can be handled with the same decoding logic.
   * @param payload The policy engine payload containing the function selector and calldata
   * @return An array of two parameters: PARAM_ACCOUNT and PARAM_AMOUNT
   */
  function extract(IPolicyEngine.Payload calldata payload)
    external
    pure
    override
    returns (IPolicyEngine.Parameter[] memory)
  {
    uint256 amount = 0;
    address account;

    // Both mint and burn functions have the same signature: (address account, uint256 amount)
    if (payload.selector == IToken.mint.selector || payload.selector == IToken.burn.selector) {
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
