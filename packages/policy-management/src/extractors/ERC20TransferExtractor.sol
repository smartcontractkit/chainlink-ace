// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IExtractor} from "@chainlink/policy-management/interfaces/IExtractor.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title ERC20TransferExtractor
 * @notice Extracts transfer parameters from ERC20 token transfer and transferFrom function calls.
 * @dev This extractor supports both transfer() and transferFrom() function selectors and extracts
 *      the from address, to address, and amount parameters. For transfer() calls, the from address
 *      is set to the transaction sender (msg.sender).
 */
contract ERC20TransferExtractor is IExtractor {
  /// @notice Parameter key for the sender/from address in transfer operations
  bytes32 public constant PARAM_FROM = keccak256("from");

  /// @notice Parameter key for the recipient/to address in transfer operations
  bytes32 public constant PARAM_TO = keccak256("to");

  /// @notice Parameter key for the amount being transferred
  bytes32 public constant PARAM_AMOUNT = keccak256("amount");

  /**
   * @inheritdoc IExtractor
   * @dev Extracts parameters from ERC20 transfer and transferFrom function calls.
   *      - For transfer(address to, uint256 amount): from = msg.sender
   *      - For transferFrom(address from, address to, uint256 amount): from = decoded from parameter
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

    // Handle transfer(address to, uint256 amount) - from is the sender
    if (payload.selector == IERC20.transfer.selector) {
      from = payload.sender;
      (to, amount) = abi.decode(payload.data, (address, uint256));
      // Handle transferFrom(address from, address to, uint256 amount)
    } else if (payload.selector == IERC20.transferFrom.selector) {
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
