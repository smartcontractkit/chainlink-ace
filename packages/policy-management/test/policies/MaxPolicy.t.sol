// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IPolicyEngine, PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {MaxPolicy} from "@chainlink/policy-management/policies/MaxPolicy.sol";
import {ERC20TransferExtractor} from "@chainlink/policy-management/extractors/ERC20TransferExtractor.sol";
import {MockTokenUpgradeable} from "../helpers/MockTokenUpgradeable.sol";
import {BaseProxyTest} from "../helpers/BaseProxyTest.sol";

contract MaxPolicyTest is BaseProxyTest {
  PolicyEngine public policyEngine;
  MockTokenUpgradeable public token;
  MaxPolicy public policy;
  address public deployer;
  address public recipient;

  function setUp() public {
    deployer = makeAddr("deployer");
    recipient = makeAddr("recipient");

    vm.startPrank(deployer);

    policyEngine = _deployPolicyEngine(true, deployer);

    MaxPolicy policyImpl = new MaxPolicy();
    policy = MaxPolicy(_deployPolicy(address(policyImpl), address(policyEngine), deployer, abi.encode(100)));
    ERC20TransferExtractor extractor = new ERC20TransferExtractor();
    bytes32[] memory parameterOutputFormat = new bytes32[](1);
    parameterOutputFormat[0] = extractor.PARAM_AMOUNT();

    token = MockTokenUpgradeable(_deployMockToken(address(policyEngine)));

    policyEngine.setExtractor(MockTokenUpgradeable.transfer.selector, address(extractor));

    policyEngine.addPolicy(
      address(token), MockTokenUpgradeable.transfer.selector, address(policy), parameterOutputFormat
    );
  }

  function test_setMax_success() public {
    policy.setMax(200);
    vm.assertEq(policy.getMax(), 200);
    token.transfer(recipient, 200);
    vm.assertEq(token.balanceOf(recipient), 200);
  }

  function test_transfer_success() public {
    token.transfer(recipient, 100);
    vm.assertEq(token.balanceOf(recipient), 100);
  }

  function test_transfer_overMax_reverts() public {
    _expectRejectedRevert(
      address(policy),
      "amount exceeds maximum limit",
      MockTokenUpgradeable.transfer.selector,
      deployer,
      abi.encode(recipient, 200)
    );
    token.transfer(recipient, 200);
  }
}
