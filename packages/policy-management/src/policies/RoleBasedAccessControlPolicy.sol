// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {Policy} from "@chainlink/policy-management/core/Policy.sol";

/**
 * @title RoleBasedAccessControlPolicy
 * @notice A policy that allows or denies method calls based on the roles of the sender.
 * @dev This policy uses OpenZeppelin's AccessControlUpgradeable to manage roles and permissions. The initial owner of
 * the policy is granted the DEFAULT_ADMIN_ROLE, which allows them to grant and revoke any role. Users can also make use
 * of roleAdmin to grant account permission to manage specific roles.
 *
 * # Usage
 * Grant the operation allowance to a role. This will allow any account with that role to perform the operation.
 * ```
 * bytes32 role = keccak256(abi.encode("roleName"));
 * grantOperationAllowanceToRole(Token.transfer.selector, role);
 * grantRole(role, account);
 * ```
 */
contract RoleBasedAccessControlPolicy is Policy, AccessControlUpgradeable {
  /**
   * @notice Emitted when the operation allowance is granted to a role.
   * @param operation The operation allowance to be granted.
   * @param role The role that is granted the operation allowance.
   */
  event OperationAllowanceGrantedToRole(bytes4 operation, bytes32 role);
  /**
   * @notice Emitted when the operation allowance is removed from a role.
   * @param operation The operation allowance to be removed.
   * @param role The role that is removed the operation allowance.
   */
  event OperationAllowanceRemovedFromRole(bytes4 operation, bytes32 role);

  /// @custom:storage-location erc7201:policy-management.RoleBasedAccessControlPolicy
  struct RoleBasedAccessControlPolicyStorage {
    /// @notice The mapping of operation allowances to roles. Each operation can have multiple roles that are allowed to
    /// perform it.
    mapping(bytes4 operation => bytes32[] roles) rolesByOperation;
  }

  // keccak256(abi.encode(uint256(keccak256("policy-management.RoleBasedAccessControlPolicy")) - 1)) &
  // ~bytes32(uint256(0xff))
  bytes32 private constant RoleBasedAccessControlPolicyStorageLocation =
    0xcebcf55b92595d67a9ed71c4c21ff1d547eba811760bfc05d1f636b4330cd900;

  function _getRoleBasedAccessControlPolicyStorage()
    private
    pure
    returns (RoleBasedAccessControlPolicyStorage storage $)
  {
    assembly {
      $.slot := RoleBasedAccessControlPolicyStorageLocation
    }
  }

  /**
   * @notice Configures the policy by granting the initial owner the `DEFAULT_ADMIN_ROLE`.
   * @dev No parameters are expected or decoded from the input. The owner is granted the `DEFAULT_ADMIN_ROLE`
   *      using OpenZeppelin's AccessControl mechanism. This role allows the owner to grant and revoke other roles.
   */
  function configure(bytes calldata) internal override {
    address owner = owner();
    bool granted = _grantRole(DEFAULT_ADMIN_ROLE, owner);
    require(granted, "failed to grant DEFAULT_ADMIN_ROLE");
  }

  /**
   * @notice Grants the operation allowance to a role. This will allow any account with that role to perform the
   * operation.
   * @param operation The operation allowance to be granted.
   * @param role The role that is granted the operation allowance.
   */
  function grantOperationAllowanceToRole(bytes4 operation, bytes32 role) public onlyOwner {
    RoleBasedAccessControlPolicyStorage storage $ = _getRoleBasedAccessControlPolicyStorage();
    uint256 length = $.rolesByOperation[operation].length;
    for (uint256 i = 0; i < length; i++) {
      if ($.rolesByOperation[operation][i] == role) {
        revert("Role already has operation allowance");
      }
    }
    $.rolesByOperation[operation].push(role);
    emit OperationAllowanceGrantedToRole(operation, role);
  }

  /**
   * @notice Removes the operation allowance from a role. This will revoke the ability of any account with that role to
   * perform the operation.
   * @param operation The operation allowance to be removed.
   * @param role The role that is removed the operation allowance.
   */
  function removeOperationAllowanceFromRole(bytes4 operation, bytes32 role) public onlyOwner {
    RoleBasedAccessControlPolicyStorage storage $ = _getRoleBasedAccessControlPolicyStorage();
    uint256 length = $.rolesByOperation[operation].length;
    for (uint256 i = 0; i < length; i++) {
      if ($.rolesByOperation[operation][i] == role) {
        $.rolesByOperation[operation][i] = $.rolesByOperation[operation][length - 1];
        $.rolesByOperation[operation].pop();
        emit OperationAllowanceRemovedFromRole(operation, role);
        return;
      }
    }
    revert("Role does not have operation allowance");
  }

  /**
   * @notice Checks if the account has any of the roles that are allowed to perform the operation.
   * @param operation The function selector of the operation.
   * @param account The address of the account to check.
   * @return isAllowed true if the account has any of the roles that are allowed to perform the operation, false
   * otherwise.
   */
  function hasAllowedRole(bytes4 operation, address account) public view returns (bool) {
    RoleBasedAccessControlPolicyStorage storage $ = _getRoleBasedAccessControlPolicyStorage();
    bytes32[] memory roles = $.rolesByOperation[operation];
    uint256 length = roles.length;
    for (uint256 i = 0; i < length; i++) {
      if (hasRole(roles[i], account)) {
        return true;
      }
    }
    return false;
  }

  /**
   * @notice Function to be called by the policy engine to check if execution is allowed.
   * @param caller The address of the sender.
   * @param selector The function selector of the method being called.
   * @param parameters None expected for this policy.
   * @return result The result of the policy check.
   */
  function run(
    address caller,
    address, /*subject*/
    bytes4 selector,
    bytes[] calldata parameters,
    bytes calldata /*context*/
  )
    public
    view
    override
    returns (IPolicyEngine.PolicyResult)
  {
    // expected parameters: none
    // solhint-disable-next-line gas-custom-errors
    if (parameters.length != 0) {
      revert IPolicyEngine.InvalidConfiguration("expected 0 parameters");
    }

    if (!hasAllowedRole(selector, caller)) {
      return IPolicyEngine.PolicyResult.Rejected;
    }

    return IPolicyEngine.PolicyResult.Continue;
  }

  function supportsInterface(bytes4 interfaceId) public view override(Policy, AccessControlUpgradeable) returns (bool) {
    return super.supportsInterface(interfaceId);
  }
}
