// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {BaseProxyTest} from "../helpers/BaseProxyTest.sol";
import {IPolicyEngine, PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {OnlyOwnerPolicy} from "@chainlink/policy-management/policies/OnlyOwnerPolicy.sol";
import {MockToken} from "../helpers/MockToken.sol";

contract OnlyOwnerPolicyTest is BaseProxyTest {
  PolicyEngine public policyEngine;
  MockToken public token;
  OnlyOwnerPolicy public policy;
  address public deployer;
  address public account;
  address public recipient;

  function setUp() public {
    deployer = makeAddr("deployer");
    account = makeAddr("account");
    recipient = makeAddr("recipient");

    vm.startPrank(deployer, deployer);

    policyEngine = PolicyEngine(_deployPolicyEngine(IPolicyEngine.PolicyResult.Allowed, deployer));

    OnlyOwnerPolicy policyImpl = new OnlyOwnerPolicy();
    policy = OnlyOwnerPolicy(_deployPolicy(address(policyImpl), address(policyEngine), deployer, new bytes(0)));

    token = MockToken(_deployMockToken(address(policyEngine)));

    policyEngine.addPolicy(address(token), MockToken.transfer.selector, address(policy), new bytes32[](0));
  }

  function test_transfer_owner_success() public {
    vm.startPrank(deployer, deployer);
    token.transfer(recipient, 100);
    vm.assertEq(token.balanceOf(recipient), 100);
  }

  function test_transfer_notOwner_reverts() public {
    vm.startPrank(account, account);
    vm.expectPartialRevert(IPolicyEngine.PolicyRunRejected.selector);
    token.transfer(recipient, 100);
  }
}
