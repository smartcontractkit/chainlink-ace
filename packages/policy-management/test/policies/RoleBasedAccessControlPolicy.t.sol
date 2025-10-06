// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {RoleBasedAccessControlPolicy} from "@chainlink/policy-management/policies/RoleBasedAccessControlPolicy.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {MockToken} from "../helpers/MockToken.sol";
import {BaseProxyTest} from "../helpers/BaseProxyTest.sol";

contract RoleBasedAccessControlPolicyTest is BaseProxyTest {
  RoleBasedAccessControlPolicy policy;
  PolicyEngine public policyEngine;
  MockToken public token;
  address public deployer;
  address public txSender;
  address public recipient;

  function setUp() public {
    deployer = makeAddr("deployer");
    txSender = makeAddr("txSender");

    vm.startPrank(deployer);

    policyEngine = _deployPolicyEngine(IPolicyEngine.PolicyResult.Allowed, deployer);

    token = MockToken(_deployMockToken(address(policyEngine)));

    RoleBasedAccessControlPolicy policyImpl = new RoleBasedAccessControlPolicy();
    policy = RoleBasedAccessControlPolicy(_deployPolicy(address(policyImpl), address(policyEngine), deployer, ""));

    policyEngine.addPolicy(address(token), MockToken.transfer.selector, address(policy), new bytes32[](0));
  }

  function test_grantRoleRevokeRole_deployer_succeeds() public {
    bytes32 someRole = keccak256("someRole");

    vm.startPrank(deployer);

    vm.expectEmit();
    emit IAccessControl.RoleGranted(someRole, txSender, deployer);
    policy.grantRole(someRole, txSender);
    assertEq(policy.hasRole(someRole, txSender), true);
    vm.expectEmit();
    emit IAccessControl.RoleRevoked(someRole, txSender, deployer);
    policy.revokeRole(someRole, txSender);
    assertEq(policy.hasRole(someRole, txSender), false);
  }

  function test_grantRoleRevokeRole_nonDeployer_fails() public {
    bytes32 someRole = keccak256("someRole");
    address nonDeployer = makeAddr("nonDeployer");

    vm.startPrank(nonDeployer);

    vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, nonDeployer, 0x00));
    policy.grantRole(someRole, txSender);
    vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, nonDeployer, 0x00));
    policy.revokeRole(someRole, txSender);
  }

  function test_grantRoleRevokeRole_roleAdmin_succeeds() public {
    bytes32 someRole = keccak256("someRole");
    address admin = makeAddr("admin");

    // grant admin role of "someRole" to admin
    vm.startPrank(deployer);
    policy.grantRole(policy.getRoleAdmin(someRole), admin);

    vm.startPrank(admin);
    vm.expectEmit();
    emit IAccessControl.RoleGranted(someRole, txSender, admin);
    policy.grantRole(someRole, txSender);
    assertEq(policy.hasRole(someRole, txSender), true);
    vm.expectEmit();
    emit IAccessControl.RoleRevoked(someRole, txSender, admin);
    policy.revokeRole(someRole, txSender);
    assertEq(policy.hasRole(someRole, txSender), false);
  }

  function test_grantOperationAllowanceToRole_succeeds() public {
    bytes32 role = keccak256("role");
    vm.startPrank(deployer);

    // grant operation allowance to role
    vm.expectEmit();
    emit RoleBasedAccessControlPolicy.OperationAllowanceGrantedToRole(MockToken.transfer.selector, role);
    policy.grantOperationAllowanceToRole(MockToken.transfer.selector, role);
  }

  function test_grantOperationAllowanceToRole_alreadyExist_fails() public {
    bytes32 role = keccak256("role");
    vm.startPrank(deployer);

    // grant operation allowance to role (sanity check)
    vm.expectEmit();
    emit RoleBasedAccessControlPolicy.OperationAllowanceGrantedToRole(MockToken.transfer.selector, role);
    policy.grantOperationAllowanceToRole(MockToken.transfer.selector, role);

    // grant again (revert)
    vm.expectRevert("Role already has operation allowance");
    policy.grantOperationAllowanceToRole(MockToken.transfer.selector, role);
  }

  function test_removeOperationAllowanceFromRole_succeeds() public {
    bytes32 role = keccak256("role");
    vm.startPrank(deployer);

    // grant operation allowance to role (sanity check)
    vm.expectEmit();
    emit RoleBasedAccessControlPolicy.OperationAllowanceGrantedToRole(MockToken.transfer.selector, role);
    policy.grantOperationAllowanceToRole(MockToken.transfer.selector, role);

    // remove operation allowance from role
    vm.expectEmit();
    emit RoleBasedAccessControlPolicy.OperationAllowanceRemovedFromRole(MockToken.transfer.selector, role);
    policy.removeOperationAllowanceFromRole(MockToken.transfer.selector, role);
  }

  function test_removeOperationAllowanceFromRole_invalidOperation_fails() public {
    bytes32 role = keccak256("role");
    vm.startPrank(deployer);

    // remove invalid operation allowance from role (revert)
    vm.expectRevert("Role does not have operation allowance");
    policy.removeOperationAllowanceFromRole(MockToken.transfer.selector, role);
  }

  function test_transfer_senderWithoutRole_reverts() public {
    vm.startPrank(txSender);

    vm.expectPartialRevert(IPolicyEngine.PolicyRunRejected.selector);
    token.transfer(recipient, 100);
  }

  function test_transfer_withRoleAssociatedToOperation_succeeds() public {
    vm.startPrank(deployer);
    bytes32 allowedRole = keccak256("allowedRole");
    policy.grantOperationAllowanceToRole(MockToken.transfer.selector, allowedRole);
    policy.grantRole(allowedRole, txSender);

    vm.startPrank(txSender);

    token.transfer(recipient, 100);

    assert(token.balanceOf(recipient) == 100);
  }

  function test_transfer_withRoleAssignedToUserButNotAssociatedToOperation_reverts() public {
    vm.startPrank(deployer);
    bytes32 someRole = keccak256("someRole");
    policy.grantRole(someRole, txSender);

    vm.startPrank(txSender);

    vm.expectPartialRevert(IPolicyEngine.PolicyRunRejected.selector);
    token.transfer(recipient, 100);
  }

  function test_transfer_withRoleAssignedToUserAndRevokedFromOperation_reverts() public {
    vm.startPrank(deployer);
    bytes32 allowedRole = keccak256("allowedRole");
    policy.grantOperationAllowanceToRole(MockToken.transfer.selector, allowedRole);
    policy.grantRole(allowedRole, txSender);

    // sanity check
    vm.startPrank(txSender);
    token.transfer(recipient, 100);
    assertEq(token.balanceOf(recipient), 100);

    vm.startPrank(deployer);
    policy.removeOperationAllowanceFromRole(MockToken.transfer.selector, allowedRole);

    vm.startPrank(txSender);
    vm.expectPartialRevert(IPolicyEngine.PolicyRunRejected.selector);
    token.transfer(recipient, 100);
    assertEq(token.balanceOf(recipient), 100);
  }

  function test_transfer_senderWithRoleAssociatedToOperationButRevoked_reverts() public {
    vm.startPrank(deployer);
    bytes32 allowedRole = keccak256("allowedRole");
    policy.grantOperationAllowanceToRole(MockToken.transfer.selector, allowedRole);
    policy.grantRole(allowedRole, txSender);

    // sanity check
    vm.startPrank(txSender);
    token.transfer(recipient, 100);
    assert(token.balanceOf(recipient) == 100);

    vm.startPrank(deployer);
    policy.revokeRole(allowedRole, txSender);

    vm.startPrank(txSender);
    vm.expectPartialRevert(IPolicyEngine.PolicyRunRejected.selector);
    token.transfer(recipient, 100);

    assert(token.balanceOf(recipient) == 100);
  }

  function test_transfer_senderWithDifferentRole_reverts() public {
    vm.startPrank(deployer);
    bytes32 allowedRole = keccak256("allowedRole");
    policy.grantOperationAllowanceToRole(MockToken.transfer.selector, allowedRole);

    bytes32 anotherRole = keccak256("anotherRole");
    policy.grantRole(anotherRole, txSender);

    vm.startPrank(txSender);
    vm.expectPartialRevert(IPolicyEngine.PolicyRunRejected.selector);
    token.transfer(recipient, 100);
  }
}
