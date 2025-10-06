// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {Policy} from "@chainlink/policy-management/core/Policy.sol";

/**
 * @title BypassPolicy
 * @notice A policy that permits method calls if all of the addresses are on an allowlist, overriding and bypassing any
 * subsequent policies in the chain.
 */
contract BypassPolicy is Policy {
  /// @custom:storage-location erc7201:policy-management.BypassPolicy
  struct BypassPolicyStorage {
    /// @notice If the address is on this list, method calls will always be allowed.
    mapping(address account => bool isAllowed) allowList;
  }

  // keccak256(abi.encode(uint256(keccak256("policy-management.BypassPolicy")) - 1)) & ~bytes32(uint256(0xff))
  bytes32 private constant BypassPolicyStorageLocation =
    0x58a84146d7d8a792905a46c0c78d69c71c1cf7909b1068f119d17e740a8cb600;

  function _getBypassPolicyStorage() private pure returns (BypassPolicyStorage storage $) {
    assembly {
      $.slot := BypassPolicyStorageLocation
    }
  }

  /**
   * @notice Adds the account to the bypass list.
   * @dev Throws if the account is already in the bypass list.
   * @param account The address to add to the bypass list.
   */
  function allowAddress(address account) public onlyOwner {
    BypassPolicyStorage storage $ = _getBypassPolicyStorage();
    require(!$.allowList[account], "Account already in bypass list");
    $.allowList[account] = true;
  }

  /**
   * @notice Removes the account from the bypass list.
   * @dev Throws if the account is not in the bypass list.
   * @param account The address to remove from the bypass list.
   */
  function disallowAddress(address account) public onlyOwner {
    BypassPolicyStorage storage $ = _getBypassPolicyStorage();
    require($.allowList[account], "Account not in bypass list");
    $.allowList[account] = false;
  }

  /**
   * @notice Checks if the account is on the bypass list.
   * @param account The address to check.
   * @return addressAllowed if the account is on the bypass list, false otherwise.
   */
  function addressAllowed(address account) public view returns (bool) {
    BypassPolicyStorage storage $ = _getBypassPolicyStorage();
    return $.allowList[account];
  }

  /**
   * @notice Function to be called by the policy engine to check if execution is allowed.
   * @param parameters encoded policy parameters.
   *        [account(address),...] List of addresses to check for present on the bypass list.
   * @return result The result of the policy check.
   */
  function run(
    address, /*caller*/
    address, /*subject*/
    bytes4, /*selector*/
    bytes[] calldata parameters, /*parameters*/
    bytes calldata /*context*/
  )
    public
    view
    override
    returns (IPolicyEngine.PolicyResult)
  {
    require(parameters.length >= 1, "expected at least 1 parameter");
    // Gas optimization: load storage reference once
    BypassPolicyStorage storage $ = _getBypassPolicyStorage();
    for (uint256 i = 0; i < parameters.length; i++) {
      address account = abi.decode(parameters[i], (address));
      if (!$.allowList[account]) {
        return IPolicyEngine.PolicyResult.Continue;
      }
    }
    return IPolicyEngine.PolicyResult.Allowed;
  }
}
