// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IExtractor} from "@chainlink/policy-management/interfaces/IExtractor.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title ERC20ApproveExtractor
 * @notice Extracts parameters from ERC20 token approve function calls.
 * @dev This extractor supports the approve() function selector and extracts the account (msg.sender),
 *      spender address, and amount parameters from the function calldata.
 */
contract ERC20ApproveExtractor is IExtractor {
  /// @notice Parameter key for the account granting the approval (msg.sender)
  bytes32 public constant PARAM_ACCOUNT = keccak256("account");

  /// @notice Parameter key for the spender address being approved
  bytes32 public constant PARAM_SPENDER = keccak256("spender");

  /// @notice Parameter key for the amount being approved
  bytes32 public constant PARAM_AMOUNT = keccak256("amount");

  /**
   * @inheritdoc IExtractor
   * @dev Extracts parameters from ERC20 approve(address spender, uint256 amount) function calls.
   *      The account parameter is set to msg.sender since approve is called by the token owner.
   * @param payload The policy engine payload containing the function selector and calldata
   * @return An array of three parameters: PARAM_ACCOUNT, PARAM_SPENDER, and PARAM_AMOUNT
   */
  function extract(IPolicyEngine.Payload calldata payload)
    public
    pure
    virtual
    returns (IPolicyEngine.Parameter[] memory)
  {
    address account = address(0);
    address spender = address(0);
    uint256 amount = 0;

    // Handle approve(address spender, uint256 amount) - account is the sender
    if (payload.selector == IERC20.approve.selector) {
      account = payload.sender;
      (spender, amount) = abi.decode(payload.data, (address, uint256));
    } else {
      revert IPolicyEngine.UnsupportedSelector(payload.selector);
    }

    // Build the parameter array with extracted values
    IPolicyEngine.Parameter[] memory result = new IPolicyEngine.Parameter[](3);
    result[0] = IPolicyEngine.Parameter(PARAM_ACCOUNT, abi.encode(account));
    result[1] = IPolicyEngine.Parameter(PARAM_SPENDER, abi.encode(spender));
    result[2] = IPolicyEngine.Parameter(PARAM_AMOUNT, abi.encode(amount));

    return result;
  }
}
