// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IExtractor} from "@chainlink/policy-management/interfaces/IExtractor.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {ComplianceTokenERC20} from "../../../tokens/erc-20/src/ComplianceTokenERC20.sol";

/**
 * @title ComplianceTokenMintBurnExtractor
 * @notice Extracts parameters from Compliance Token ERC20 mint and burn function calls.
 * @dev This extractor supports mint(), burn(), and burnFrom() function selectors from the
 *      ComplianceTokenERC20 contract and extracts the account and amount parameters.
 *      For burn(), the account is set to msg.sender since it burns from the caller's balance.
 */
contract ComplianceTokenMintBurnExtractor is IExtractor {
  /// @notice Parameter key for the target account address in mint/burn operations
  bytes32 public constant PARAM_ACCOUNT = keccak256("account");

  /// @notice Parameter key for the amount being minted or burned
  bytes32 public constant PARAM_AMOUNT = keccak256("amount");

  /**
   * @notice Extracts parameters from ComplianceTokenERC20 mint, burn, and burnFrom function calls.
   * @dev Handles three function signatures:
   *      - mint(address account, uint256 amount): account and amount from calldata
   *      - burnFrom(address account, uint256 amount): account and amount from calldata
   *      - burn(uint256 amount): account = msg.sender, amount from calldata
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

    // Handle mint(address account, uint256 amount) and burnFrom(address account, uint256 amount)
    if (
      payload.selector == ComplianceTokenERC20.mint.selector
        || payload.selector == ComplianceTokenERC20.burnFrom.selector
    ) {
      (account, amount) = abi.decode(payload.data, (address, uint256));
      // Handle burn(uint256 amount) - account is the sender
    } else if (payload.selector == ComplianceTokenERC20.burn.selector) {
      account = payload.sender;
      (amount) = abi.decode(payload.data, (uint256));
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
