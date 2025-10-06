// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IExtractor} from "@chainlink/policy-management/interfaces/IExtractor.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {IToken} from "../../../vendor/erc-3643/token/IToken.sol";

/**
 * @title ERC3643SetAddressFrozenExtractor
 * @notice Extracts parameters from ERC3643 token address freeze/unfreeze function calls.
 * @dev This extractor supports the setAddressFrozen() function selector from the ERC3643 token standard
 *      and extracts the target account address and freeze status (boolean value) parameters.
 */
contract ERC3643SetAddressFrozenExtractor is IExtractor {
  /// @notice Parameter key for the target account address in freeze/unfreeze operations
  bytes32 public constant PARAM_ACCOUNT = keccak256("account");

  /// @notice Parameter key for the freeze status boolean value (true = frozen, false = unfrozen)
  bytes32 public constant PARAM_VALUE = keccak256("value");

  /**
   * @notice Extracts parameters from ERC3643 setAddressFrozen function calls.
   * @dev Extracts parameters from setAddressFrozen(address account, bool value) function calls.
   *      The value parameter indicates whether to freeze (true) or unfreeze (false) the address.
   * @param payload The policy engine payload containing the function selector and calldata
   * @return An array of two parameters: PARAM_ACCOUNT and PARAM_VALUE
   */
  function extract(IPolicyEngine.Payload calldata payload)
    external
    pure
    override
    returns (IPolicyEngine.Parameter[] memory)
  {
    address account = address(0);
    bool value;

    // Handle setAddressFrozen(address account, bool value)
    if (payload.selector == IToken.setAddressFrozen.selector) {
      (account, value) = abi.decode(payload.data, (address, bool));
    } else {
      revert IPolicyEngine.UnsupportedSelector(payload.selector);
    }

    // Build the parameter array with extracted values
    IPolicyEngine.Parameter[] memory result = new IPolicyEngine.Parameter[](2);
    result[0] = IPolicyEngine.Parameter(PARAM_ACCOUNT, abi.encode(account));
    result[1] = IPolicyEngine.Parameter(PARAM_VALUE, abi.encode(value));

    return result;
  }
}
