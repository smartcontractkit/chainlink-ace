// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {Policy} from "@chainlink/policy-management/core/Policy.sol";

/**
 * @title RejectPolicy
 * @notice A policy that rejects method calls if one of the addresses is on the list.
 */
contract RejectPolicy is Policy {
  /// @custom:storage-location erc7201:policy-management.RejectPolicy
  struct RejectPolicyStorage {
    /// @notice If the address is on this list, method calls will always be rejected.
    mapping(address account => bool isRejected) rejectList;
  }

  // keccak256(abi.encode(uint256(keccak256("policy-management.RejectPolicy")) - 1)) & ~bytes32(uint256(0xff))
  bytes32 private constant RejectPolicyStorageLocation =
    0x616c7ef46b4b6f234c99b5c7b6e2de9ba93899829ad2bcb8a5a37d5cddf44600;

  function _getRejectPolicyStorage() private pure returns (RejectPolicyStorage storage $) {
    assembly {
      $.slot := RejectPolicyStorageLocation
    }
  }

  /**
   * @notice Adds the account to the reject list.
   * @dev Throws if the account is already in the reject list.
   * @param account The address to add to the reject list.
   */
  function rejectAddress(address account) public onlyOwner {
    RejectPolicyStorage storage $ = _getRejectPolicyStorage();
    require(!$.rejectList[account], "Account already in reject list");
    $.rejectList[account] = true;
  }

  /**
   * @notice Removes the account from the reject list.
   * @dev Throws if the account is not in the reject list.
   * @param account The address to remove from the reject list.
   */
  function unrejectAddress(address account) public onlyOwner {
    RejectPolicyStorage storage $ = _getRejectPolicyStorage();
    require($.rejectList[account], "Account not in reject list");
    $.rejectList[account] = false;
  }

  /**
   * @notice Checks if the account is on the reject list.
   * @param account The address to check.
   * @return addressRejected if the account is on the reject list, false otherwise.
   */
  function addressRejected(address account) public view returns (bool) {
    RejectPolicyStorage storage $ = _getRejectPolicyStorage();
    return $.rejectList[account];
  }

  /**
   * @notice Function to be called by the policy engine to check if execution is allowed.
   * @param parameters encoded policy parameters.
   *        [account(address),...] List of addresses to check for present on the reject list.
   * @return result The result of the policy check.
   */
  function run(
    address, /*caller*/
    address, /*subject*/
    bytes4, /*selector*/
    bytes[] calldata parameters,
    bytes calldata /*context*/
  )
    public
    view
    override
    returns (IPolicyEngine.PolicyResult)
  {
    require(parameters.length >= 1, "expected at least 1 parameter");
    // Gas optimization: load storage reference once
    RejectPolicyStorage storage $ = _getRejectPolicyStorage();
    for (uint256 i = 0; i < parameters.length; i++) {
      address account = abi.decode(parameters[i], (address));
      if ($.rejectList[account]) {
        revert IPolicyEngine.PolicyRejected("address is on reject list");
      }
    }
    return IPolicyEngine.PolicyResult.Continue;
  }
}
