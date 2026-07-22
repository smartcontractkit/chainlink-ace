// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {RoleBasedAccessControlPolicy} from "../../src/policies/RoleBasedAccessControlPolicy.sol";
import {IPolicyEngine} from "../../src/interfaces/IPolicyEngine.sol";
import {PolicyEngine} from "../../src/core/PolicyEngine.sol";
import {ERC3643MintBurnExtractor} from "../../src/extractors/ERC3643MintBurnExtractor.sol";
import {MockTokenUpgradeable} from "../helpers/MockTokenUpgradeable.sol";
import {BaseProxyTest} from "../helpers/BaseProxyTest.sol";

contract RoleBasedAccessControlPolicyTest is BaseProxyTest {
  RoleBasedAccessControlPolicy policy;
  PolicyEngine public policyEngine;
  MockTokenUpgradeable public token;
  address public deployer;
  address public txSender;
  address public recipient;

  function setUp() public {
    deployer = makeAddr("deployer");
    txSender = makeAddr("txSender");

    vm.startPrank(deployer);

    policyEngine = _deployPolicyEngine(true, deployer);

    token = MockTokenUpgradeable(_deployMockToken(address(policyEngine)));

    RoleBasedAccessControlPolicy policyImpl = new RoleBasedAccessControlPolicy();
    policy = RoleBasedAccessControlPolicy(_deployPolicy(address(policyImpl), address(policyEngine), deployer, ""));

    policyEngine.addPolicy(address(token), MockTokenUpgradeable.transfer.selector, address(policy), new bytes32[](0));
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
    emit RoleBasedAccessControlPolicy.OperationAllowanceGrantedToRole(MockTokenUpgradeable.transfer.selector, role);
    policy.grantOperationAllowanceToRole(MockTokenUpgradeable.transfer.selector, role);
  }

  function test_grantOperationAllowanceToRole_alreadyExist_fails() public {
    bytes32 role = keccak256("role");
    vm.startPrank(deployer);

    // grant operation allowance to role (sanity check)
    vm.expectEmit();
    emit RoleBasedAccessControlPolicy.OperationAllowanceGrantedToRole(MockTokenUpgradeable.transfer.selector, role);
    policy.grantOperationAllowanceToRole(MockTokenUpgradeable.transfer.selector, role);

    // grant again (revert)
    vm.expectRevert("Role already has operation allowance");
    policy.grantOperationAllowanceToRole(MockTokenUpgradeable.transfer.selector, role);
  }

  function test_removeOperationAllowanceFromRole_succeeds() public {
    bytes32 role = keccak256("role");
    vm.startPrank(deployer);

    // grant operation allowance to role (sanity check)
    vm.expectEmit();
    emit RoleBasedAccessControlPolicy.OperationAllowanceGrantedToRole(MockTokenUpgradeable.transfer.selector, role);
    policy.grantOperationAllowanceToRole(MockTokenUpgradeable.transfer.selector, role);

    // remove operation allowance from role
    vm.expectEmit();
    emit RoleBasedAccessControlPolicy.OperationAllowanceRemovedFromRole(MockTokenUpgradeable.transfer.selector, role);
    policy.removeOperationAllowanceFromRole(MockTokenUpgradeable.transfer.selector, role);
  }

  function test_removeOperationAllowanceFromRole_invalidOperation_fails() public {
    bytes32 role = keccak256("role");
    vm.startPrank(deployer);

    // remove invalid operation allowance from role (revert)
    vm.expectRevert("Role does not have operation allowance");
    policy.removeOperationAllowanceFromRole(MockTokenUpgradeable.transfer.selector, role);
  }

  function test_grantOperationAllowanceToRole_reGrantAfterRemove_succeeds() public {
    bytes4 operation = MockTokenUpgradeable.transfer.selector;
    bytes32 role = keccak256("role");
    vm.startPrank(deployer);

    policy.grantOperationAllowanceToRole(operation, role);
    policy.removeOperationAllowanceFromRole(operation, role);

    // The O(1) membership entry must be cleared on removal, so re-granting must not falsely revert as a duplicate.
    vm.expectEmit();
    emit RoleBasedAccessControlPolicy.OperationAllowanceGrantedToRole(operation, role);
    policy.grantOperationAllowanceToRole(operation, role);

    // And the membership entry is set again, so a duplicate grant still reverts.
    vm.expectRevert("Role already has operation allowance");
    policy.grantOperationAllowanceToRole(operation, role);
  }

  function test_removeOperationAllowanceFromRole_middleRole_keepsOthersConsistent() public {
    bytes4 operation = MockTokenUpgradeable.transfer.selector;
    bytes32 roleA = keccak256("roleA");
    bytes32 roleB = keccak256("roleB");
    bytes32 roleC = keccak256("roleC");
    vm.startPrank(deployer);

    policy.grantOperationAllowanceToRole(operation, roleA);
    policy.grantOperationAllowanceToRole(operation, roleB);
    policy.grantOperationAllowanceToRole(operation, roleC);

    // Removing the middle role swap-pops roleC into its slot; membership and array must stay in sync.
    policy.removeOperationAllowanceFromRole(operation, roleB);

    // roleB is gone: removing it again reverts via the O(1) existence check.
    vm.expectRevert("Role does not have operation allowance");
    policy.removeOperationAllowanceFromRole(operation, roleB);

    // roleA and the swapped-in roleC remain allowed: re-granting either reverts as a duplicate.
    vm.expectRevert("Role already has operation allowance");
    policy.grantOperationAllowanceToRole(operation, roleA);
    vm.expectRevert("Role already has operation allowance");
    policy.grantOperationAllowanceToRole(operation, roleC);

    // Enumeration still finds the swapped-in role: an account holding roleC is allowed for the operation.
    policy.grantRole(roleC, txSender);
    assertTrue(policy.hasAllowedRole(operation, txSender));
  }

  function test_removeOperationAllowanceFromRole_removeSwappedInRole_succeeds() public {
    bytes4 operation = MockTokenUpgradeable.transfer.selector;
    bytes32 roleA = keccak256("roleA");
    bytes32 roleB = keccak256("roleB");
    bytes32 roleC = keccak256("roleC");
    vm.startPrank(deployer);

    policy.grantOperationAllowanceToRole(operation, roleA);
    policy.grantOperationAllowanceToRole(operation, roleB);
    policy.grantOperationAllowanceToRole(operation, roleC);

    // Remove the first role; roleC (the last entry) is swapped into its slot and its stored index must be updated.
    policy.removeOperationAllowanceFromRole(operation, roleA);

    // Removing the swapped-in role must succeed via its updated index; a stale index would corrupt the removal.
    vm.expectEmit();
    emit RoleBasedAccessControlPolicy.OperationAllowanceRemovedFromRole(operation, roleC);
    policy.removeOperationAllowanceFromRole(operation, roleC);

    // Only roleB remains and is still enumerable.
    policy.grantRole(roleB, txSender);
    assertTrue(policy.hasAllowedRole(operation, txSender));

    // roleC is fully gone: removing it again reverts.
    vm.expectRevert("Role does not have operation allowance");
    policy.removeOperationAllowanceFromRole(operation, roleC);

    // roleA was removed, so it can be granted again; roleB is still present, so a duplicate grant reverts.
    policy.grantOperationAllowanceToRole(operation, roleA);
    vm.expectRevert("Role already has operation allowance");
    policy.grantOperationAllowanceToRole(operation, roleB);
  }

  function test_transfer_senderWithoutRole_reverts() public {
    vm.startPrank(txSender);

    _expectRejectedRevert(
      address(policy),
      "caller lacks required role for operation",
      MockTokenUpgradeable.transfer.selector,
      txSender,
      abi.encode(recipient, 100)
    );
    token.transfer(recipient, 100);
  }

  function test_transfer_withRoleAssociatedToOperation_succeeds() public {
    vm.startPrank(deployer);
    bytes32 allowedRole = keccak256("allowedRole");
    policy.grantOperationAllowanceToRole(MockTokenUpgradeable.transfer.selector, allowedRole);
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

    _expectRejectedRevert(
      address(policy),
      "caller lacks required role for operation",
      MockTokenUpgradeable.transfer.selector,
      txSender,
      abi.encode(recipient, 100)
    );
    token.transfer(recipient, 100);
  }

  function test_transfer_withRoleAssignedToUserAndRevokedFromOperation_reverts() public {
    vm.startPrank(deployer);
    bytes32 allowedRole = keccak256("allowedRole");
    policy.grantOperationAllowanceToRole(MockTokenUpgradeable.transfer.selector, allowedRole);
    policy.grantRole(allowedRole, txSender);

    // sanity check
    vm.startPrank(txSender);
    token.transfer(recipient, 100);
    assertEq(token.balanceOf(recipient), 100);

    vm.startPrank(deployer);
    policy.removeOperationAllowanceFromRole(MockTokenUpgradeable.transfer.selector, allowedRole);

    vm.startPrank(txSender);
    _expectRejectedRevert(
      address(policy),
      "caller lacks required role for operation",
      MockTokenUpgradeable.transfer.selector,
      txSender,
      abi.encode(recipient, 100)
    );
    token.transfer(recipient, 100);
    assertEq(token.balanceOf(recipient), 100);
  }

  function test_transfer_senderWithRoleAssociatedToOperationButRevoked_reverts() public {
    vm.startPrank(deployer);
    bytes32 allowedRole = keccak256("allowedRole");
    policy.grantOperationAllowanceToRole(MockTokenUpgradeable.transfer.selector, allowedRole);
    policy.grantRole(allowedRole, txSender);

    // sanity check
    vm.startPrank(txSender);
    token.transfer(recipient, 100);
    assert(token.balanceOf(recipient) == 100);

    vm.startPrank(deployer);
    policy.revokeRole(allowedRole, txSender);

    vm.startPrank(txSender);
    _expectRejectedRevert(
      address(policy),
      "caller lacks required role for operation",
      MockTokenUpgradeable.transfer.selector,
      txSender,
      abi.encode(recipient, 100)
    );
    token.transfer(recipient, 100);

    assert(token.balanceOf(recipient) == 100);
  }

  function test_transfer_senderWithDifferentRole_reverts() public {
    vm.startPrank(deployer);
    bytes32 allowedRole = keccak256("allowedRole");
    policy.grantOperationAllowanceToRole(MockTokenUpgradeable.transfer.selector, allowedRole);

    bytes32 anotherRole = keccak256("anotherRole");
    policy.grantRole(anotherRole, txSender);

    vm.startPrank(txSender);
    _expectRejectedRevert(
      address(policy),
      "caller lacks required role for operation",
      MockTokenUpgradeable.transfer.selector,
      txSender,
      abi.encode(recipient, 100)
    );
    token.transfer(recipient, 100);
  }

  function test_misconfiguration_failure() public {
    vm.startPrank(deployer);
    ERC3643MintBurnExtractor mintBurnExtractor = new ERC3643MintBurnExtractor();
    bytes32[] memory burnPolicyParams = new bytes32[](1);
    burnPolicyParams[0] = mintBurnExtractor.PARAM_ACCOUNT();
    policyEngine.setExtractor(MockTokenUpgradeable.burn.selector, address(mintBurnExtractor));
    policyEngine.addPolicy(address(token), MockTokenUpgradeable.burn.selector, address(policy), burnPolicyParams);

    IPolicyEngine.Payload memory payload = IPolicyEngine.Payload({
      selector: MockTokenUpgradeable.burn.selector,
      sender: deployer,
      data: abi.encode(txSender, 100),
      context: new bytes(0)
    });
    bytes memory error = abi.encodeWithSignature("InvalidParameters(string)", "expected 0 parameters");
    _expectRunError(address(policy), error, payload);
    token.burn(txSender, 100);
  }
}
