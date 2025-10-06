// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {Policy} from "@chainlink/policy-management/core/Policy.sol";

/**
 * @title OnlyAuthorizedSenderPolicy
 * @notice A policy that rejects method calls if the sender is not on the authorized list.
 */
contract OnlyAuthorizedSenderPolicy is Policy {
  /// @custom:storage-location erc7201:policy-management.OnlyAuthorizedSenderPolicy
  struct OnlyAuthorizedSenderPolicyStorage {
    /// @notice If the sender is not on this list, method calls will be rejected.
    mapping(address account => bool isAuthorized) authorizedList;
  }

  // keccak256(abi.encode(uint256(keccak256("policy-management.OnlyAuthorizedSenderPolicy")) - 1)) &
  // ~bytes32(uint256(0xff))
  bytes32 private constant OnlyAuthorizedSenderPolicyStorageLocation =
    0x55dec33488a1029cdcf3599ee8cd33d98db3bd4dac88355b9ed7e751c3fe6a00;

  function _getOnlyAuthorizedSenderPolicyStorage() private pure returns (OnlyAuthorizedSenderPolicyStorage storage $) {
    assembly {
      $.slot := OnlyAuthorizedSenderPolicyStorageLocation
    }
  }

  /**
   * @notice Adds the account to the authorized list.
   * @dev Throws if the account is already in the authorized list.
   * @param account The address to add to the authorized list.
   */
  function authorizeSender(address account) public onlyOwner {
    OnlyAuthorizedSenderPolicyStorage storage $ = _getOnlyAuthorizedSenderPolicyStorage();
    require(!$.authorizedList[account], "Account already in authorized list");
    $.authorizedList[account] = true;
  }

  /**
   * @notice Removes the account from the authorized list.
   * @dev Throws if the account is not in the authorized list.
   * @param account The address to remove from the authorized list.
   */
  function unauthorizeSender(address account) public onlyOwner {
    OnlyAuthorizedSenderPolicyStorage storage $ = _getOnlyAuthorizedSenderPolicyStorage();
    require($.authorizedList[account], "Account not in authorized list");
    $.authorizedList[account] = false;
  }

  /**
   * @notice Checks if the account is on the authorized list.
   * @param account The address to check.
   * @return senderAuthorized if the account is on the authorized list, false otherwise.
   */
  function senderAuthorized(address account) public view returns (bool) {
    OnlyAuthorizedSenderPolicyStorage storage $ = _getOnlyAuthorizedSenderPolicyStorage();
    return $.authorizedList[account];
  }

  /**
   * @notice Function to be called by the policy engine to check if execution is allowed.
   * @param caller The address of the sender.
   * @return result The result of the policy check.
   */
  function run(
    address caller, /*caller*/
    address, /*subject*/
    bytes4, /*selector*/
    bytes[] calldata, /*parameters*/
    bytes calldata /*context*/
  )
    public
    view
    override
    returns (IPolicyEngine.PolicyResult)
  {
    OnlyAuthorizedSenderPolicyStorage storage $ = _getOnlyAuthorizedSenderPolicyStorage();
    if ($.authorizedList[caller]) {
      return IPolicyEngine.PolicyResult.Continue;
    }
    return IPolicyEngine.PolicyResult.Rejected;
  }
}
