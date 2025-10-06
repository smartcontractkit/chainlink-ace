// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IPolicyEngine, PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {OnlyAuthorizedSenderPolicy} from "@chainlink/policy-management/policies/OnlyAuthorizedSenderPolicy.sol";
import {MockToken} from "../helpers/MockToken.sol";
import {BaseProxyTest} from "../helpers/BaseProxyTest.sol";

contract OnlyAuthorizedSenderPolicyTest is BaseProxyTest {
  PolicyEngine public policyEngine;
  MockToken public token;
  OnlyAuthorizedSenderPolicy public policy;
  address public deployer;
  address public sender;
  address public recipient;

  function setUp() public {
    deployer = makeAddr("deployer");
    sender = makeAddr("sender");
    recipient = makeAddr("recipient");

    vm.startPrank(deployer, deployer);

    policyEngine = _deployPolicyEngine(IPolicyEngine.PolicyResult.Allowed, deployer);

    OnlyAuthorizedSenderPolicy policyImpl = new OnlyAuthorizedSenderPolicy();
    policy = OnlyAuthorizedSenderPolicy(_deployPolicy(address(policyImpl), address(policyEngine), deployer, ""));

    token = MockToken(_deployMockToken(address(policyEngine)));

    policyEngine.addPolicy(address(token), MockToken.transfer.selector, address(policy), new bytes32[](0));
  }

  function test_authorizeSender_succeeds() public {
    vm.startPrank(deployer, deployer);

    // add the sender to the authorized list
    policy.authorizeSender(sender);
    vm.assertEq(policy.senderAuthorized(sender), true);
  }

  function test_authorizeSender_alreadyInList_fails() public {
    vm.startPrank(deployer, deployer);

    // add the sender to the authorized list (setup and sanity check)
    policy.authorizeSender(sender);
    vm.assertEq(policy.senderAuthorized(sender), true);

    // add the sender to the authorized list again (reverts)
    vm.expectRevert("Account already in authorized list");
    policy.authorizeSender(sender);
  }

  function test_unauthorizeSender_succeeds() public {
    vm.startPrank(deployer, deployer);

    // add the sender to the authorized list (setup and sanity check)
    policy.authorizeSender(sender);
    vm.assertEq(policy.senderAuthorized(sender), true);

    // remove the sender from the authorized list
    policy.unauthorizeSender(sender);
    vm.assertEq(policy.senderAuthorized(sender), false);
  }

  function test_unauthorizeSender_notInList_fails() public {
    vm.startPrank(deployer, deployer);

    // remove the sender from the authorized list (reverts)
    vm.expectRevert("Account not in authorized list");
    policy.unauthorizeSender(sender);
  }

  function test_transfer_inList_succeeds() public {
    vm.startPrank(deployer, deployer);

    // add the sender to the allow list
    policy.authorizeSender(sender);
    vm.assertEq(policy.senderAuthorized(sender), true);

    vm.startPrank(sender, sender);

    // transfer from sender to recipient
    token.transfer(recipient, 100);
    vm.assertEq(token.balanceOf(recipient), 100);
  }

  function test_transfer_notInList_fails() public {
    vm.startPrank(sender, sender);

    // transfer from sender to recipient (reverts)
    vm.expectRevert(
      abi.encodeWithSelector(IPolicyEngine.PolicyRunRejected.selector, MockToken.transfer.selector, address(policy))
    );
    token.transfer(recipient, 100);
  }
}
