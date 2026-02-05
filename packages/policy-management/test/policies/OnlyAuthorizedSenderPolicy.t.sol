// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IPolicyEngine, PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {OnlyAuthorizedSenderPolicy} from "@chainlink/policy-management/policies/OnlyAuthorizedSenderPolicy.sol";
import {MockTokenUpgradeable} from "../helpers/MockTokenUpgradeable.sol";
import {BaseProxyTest} from "../helpers/BaseProxyTest.sol";

contract OnlyAuthorizedSenderPolicyTest is BaseProxyTest {
  PolicyEngine public policyEngine;
  MockTokenUpgradeable public token;
  OnlyAuthorizedSenderPolicy public policy;
  address public deployer;
  address public sender;
  address public recipient;

  function setUp() public {
    deployer = makeAddr("deployer");
    sender = makeAddr("sender");
    recipient = makeAddr("recipient");

    vm.startPrank(deployer, deployer);

    policyEngine = _deployPolicyEngine(true, deployer);

    OnlyAuthorizedSenderPolicy policyImpl = new OnlyAuthorizedSenderPolicy();
    policy =
      OnlyAuthorizedSenderPolicy(_deployPolicy(address(policyImpl), address(policyEngine), address(policyEngine), ""));

    token = MockTokenUpgradeable(_deployMockToken(address(policyEngine)));

    policyEngine.addPolicy(address(token), MockTokenUpgradeable.transfer.selector, address(policy), new bytes32[](0));
  }

  function test_authorizeSender_invalidVersion_fails() public {
    vm.startPrank(deployer, deployer);

    // add the sender to the authorized list
    policyEngine.setPolicyConfiguration(
      address(policy), 0, OnlyAuthorizedSenderPolicy.authorizeSender.selector, abi.encode(sender)
    );

    vm.assertEq(policy.senderAuthorized(sender), true);

    vm.expectRevert(
      abi.encodeWithSelector(IPolicyEngine.PolicyConfigurationVersionError.selector, address(policy), 0, 1)
    );
    policyEngine.setPolicyConfiguration(
      address(policy), 0, OnlyAuthorizedSenderPolicy.authorizeSender.selector, abi.encode(sender)
    );
  }

  function test_authorizeSender_succeeds() public {
    vm.startPrank(deployer, deployer);

    vm.expectEmit(true, true, true, true);
    emit OnlyAuthorizedSenderPolicy.SenderAuthorized(sender);

    // add the sender to the authorized list
    policyEngine.setPolicyConfiguration(
      address(policy),
      policyEngine.getPolicyConfigVersion(address(policy)),
      OnlyAuthorizedSenderPolicy.authorizeSender.selector,
      abi.encode(sender)
    );

    vm.assertEq(policy.senderAuthorized(sender), true);
  }

  function test_authorizeSender_alreadyInList_fails() public {
    vm.startPrank(deployer, deployer);

    // add the sender to the authorized list (setup and sanity check)
    policyEngine.setPolicyConfiguration(
      address(policy),
      policyEngine.getPolicyConfigVersion(address(policy)),
      OnlyAuthorizedSenderPolicy.authorizeSender.selector,
      abi.encode(sender)
    );
    vm.assertEq(policy.senderAuthorized(sender), true);

    uint256 version = policyEngine.getPolicyConfigVersion(address(policy));
    // add the sender to the authorized list again (reverts)
    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyConfigurationError.selector,
        address(policy),
        abi.encodeWithSignature("Error(string)", "Account already in authorized list")
      )
    );
    policyEngine.setPolicyConfiguration(
      address(policy), version, OnlyAuthorizedSenderPolicy.authorizeSender.selector, abi.encode(sender)
    );
  }

  function test_unauthorizeSender_succeeds() public {
    vm.startPrank(deployer, deployer);

    vm.expectEmit(true, true, true, true);
    emit OnlyAuthorizedSenderPolicy.SenderAuthorized(sender);

    // add the sender to the authorized list (setup and sanity check)
    policyEngine.setPolicyConfiguration(
      address(policy),
      policyEngine.getPolicyConfigVersion(address(policy)),
      OnlyAuthorizedSenderPolicy.authorizeSender.selector,
      abi.encode(sender)
    );
    vm.assertEq(policy.senderAuthorized(sender), true);

    // remove the sender from the authorized list
    policyEngine.setPolicyConfiguration(
      address(policy),
      policyEngine.getPolicyConfigVersion(address(policy)),
      OnlyAuthorizedSenderPolicy.unauthorizeSender.selector,
      abi.encode(sender)
    );
    vm.assertEq(policy.senderAuthorized(sender), false);
  }

  function test_unauthorizeSender_notInList_fails() public {
    vm.startPrank(deployer, deployer);

    uint256 version = policyEngine.getPolicyConfigVersion(address(policy));
    // remove the sender from the authorized list (reverts)
    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyConfigurationError.selector,
        address(policy),
        abi.encodeWithSignature("Error(string)", "Account not in authorized list")
      )
    );
    policyEngine.setPolicyConfiguration(
      address(policy), version, OnlyAuthorizedSenderPolicy.unauthorizeSender.selector, abi.encode(sender)
    );
  }

  function test_transfer_inList_succeeds() public {
    vm.startPrank(deployer, deployer);

    // add the sender to the allow list
    policyEngine.setPolicyConfiguration(
      address(policy),
      policyEngine.getPolicyConfigVersion(address(policy)),
      OnlyAuthorizedSenderPolicy.authorizeSender.selector,
      abi.encode(sender)
    );
    vm.assertEq(policy.senderAuthorized(sender), true);

    vm.startPrank(sender, sender);

    // transfer from sender to recipient
    token.transfer(recipient, 100);
    vm.assertEq(token.balanceOf(recipient), 100);
  }

  function test_transfer_notInList_fails() public {
    vm.startPrank(sender, sender);

    // transfer from sender to recipient (reverts)
    _expectRejectedRevert(
      address(policy),
      "sender is not authorized",
      MockTokenUpgradeable.transfer.selector,
      sender,
      abi.encode(recipient, 100)
    );
    token.transfer(recipient, 100);
  }
}
