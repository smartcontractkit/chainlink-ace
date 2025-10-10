// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {Policy} from "@chainlink/policy-management/core/Policy.sol";

/**
 * @title AllowPolicy
 * @notice A policy that permits method calls if all of the addresses are on an allowlist.
 */
contract AllowPolicy is Policy {
  /**
   * @notice Emitted when an address is added to the allow list.
   * @param account The address that was added to the allow list.
   */
  event AddressAllowed(address indexed account);

  /**
   * @notice Emitted when an address is removed from the allow list.
   * @param account The address that was removed from the allow list.
   */
  event AddressDisallowed(address indexed account);

  /// @custom:storage-location erc7201:policy-management.AllowPolicy
  struct AllowPolicyStorage {
    /// @notice If the address is not on this list, method calls will always be rejected.
    mapping(address account => bool isAllowed) allowList;
  }

  // keccak256(abi.encode(uint256(keccak256("policy-management.AllowPolicy")) - 1)) & ~bytes32(uint256(0xff))
  bytes32 private constant AllowPolicyStorageLocation =
    0x765cab6c47f7237f7aa9342433ee5465ec3e83a263328a78226aaa7d8727a800;

  function _getAllowPolicyStorage() private pure returns (AllowPolicyStorage storage $) {
    assembly {
      $.slot := AllowPolicyStorageLocation
    }
  }

  /**
   * @notice Adds the account to the allow list.
   * @dev Throws if the account is already in the allow list.
   * @param account The address to add to the allow list.
   */
  function allowAddress(address account) public onlyOwner {
    AllowPolicyStorage storage $ = _getAllowPolicyStorage();
    require(!$.allowList[account], "Account already in allow list");
    $.allowList[account] = true;
    emit AddressAllowed(account);
  }

  /**
   * @notice Removes the account from the allow list.
   * @dev Throws if the account is not in the allow list.
   * @param account The address to remove from the allow list.
   */
  function disallowAddress(address account) public onlyOwner {
    AllowPolicyStorage storage $ = _getAllowPolicyStorage();
    require($.allowList[account], "Account not in allow list");
    $.allowList[account] = false;
    emit AddressDisallowed(account);
  }

  /**
   * @notice Checks if the account is on the allow list.
   * @param account The address to check.
   * @return addressAllowed if the account is on the allow list, false otherwise.
   */
  function addressAllowed(address account) public view returns (bool) {
    return _getAllowPolicyStorage().allowList[account];
  }

  /**
   * @notice Function to be called by the policy engine to check if execution is allowed.
   * @param parameters encoded policy parameters.
   *        [account(address),...] List of addresses to check for present on the allow list.
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

    // Gas optimization: Load storage reference once instead of calling _getAllowPolicyStorage() in each iteration
    AllowPolicyStorage storage $ = _getAllowPolicyStorage();

    for (uint256 i = 0; i < parameters.length; i++) {
      address account = abi.decode(parameters[i], (address));
      if (!$.allowList[account]) {
        revert IPolicyEngine.PolicyRejected("address is not on allow list");
      }
    }
    return IPolicyEngine.PolicyResult.Continue;
  }
}
