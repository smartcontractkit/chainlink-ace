// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IExtractor} from "@chainlink/policy-management/interfaces/IExtractor.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {IToken} from "../../../vendor/erc-3643/token/IToken.sol";

/**
 * @title ERC3643ForcedTransferExtractor
 * @notice Extracts parameters from ERC3643 token forced transfer function calls.
 * @dev This extractor supports the forcedTransfer() function selector from the ERC3643 token standard
 *      and extracts the from address, to address, and amount parameters from the function calldata.
 *      Forced transfers allow authorized agents to move tokens between addresses without approval.
 */
contract ERC3643ForcedTransferExtractor is IExtractor {
  /// @notice Parameter key for the sender/from address in forced transfer operations
  bytes32 public constant PARAM_FROM = keccak256("from");

  /// @notice Parameter key for the recipient/to address in forced transfer operations
  bytes32 public constant PARAM_TO = keccak256("to");

  /// @notice Parameter key for the amount being forcefully transferred
  bytes32 public constant PARAM_AMOUNT = keccak256("amount");

  /**
   * @inheritdoc IExtractor
   * @dev Extracts parameters from ERC3643 forcedTransfer(address from, address to, uint256 amount) function calls.
   * @param payload The policy engine payload containing the function selector and calldata
   * @return An array of three parameters: PARAM_FROM, PARAM_TO, and PARAM_AMOUNT
   */
  function extract(IPolicyEngine.Payload calldata payload)
    public
    pure
    virtual
    returns (IPolicyEngine.Parameter[] memory)
  {
    address from = address(0);
    address to = address(0);
    uint256 amount = 0;

    // Handle forcedTransfer(address from, address to, uint256 amount)
    if (payload.selector == IToken.forcedTransfer.selector) {
      (from, to, amount) = abi.decode(payload.data, (address, address, uint256));
    } else {
      revert IPolicyEngine.UnsupportedSelector(payload.selector);
    }

    // Build the parameter array with extracted values
    IPolicyEngine.Parameter[] memory result = new IPolicyEngine.Parameter[](3);
    result[0] = IPolicyEngine.Parameter(PARAM_FROM, abi.encode(from));
    result[1] = IPolicyEngine.Parameter(PARAM_TO, abi.encode(to));
    result[2] = IPolicyEngine.Parameter(PARAM_AMOUNT, abi.encode(amount));

    return result;
  }
}
