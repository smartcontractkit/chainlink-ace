// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IPolicyEngine, PolicyEngine} from "../src/core/PolicyEngine.sol";
import {MaxPolicy} from "../src/policies/MaxPolicy.sol";
import {MockTokenExtractor} from "./helpers/MockTokenExtractor.sol";
import {MockToken} from "./helpers/MockToken.sol";
import {BaseProxyTest} from "./helpers/BaseProxyTest.sol";

contract SecureToken_MaxPolicy is BaseProxyTest {
  MockToken public token;
  PolicyEngine public policyEngine;

  function setUp() public {
    policyEngine = _deployPolicyEngine(IPolicyEngine.PolicyResult.Allowed, address(this));

    token = MockToken(_deployMockToken(address(policyEngine)));

    MaxPolicy policyImpl = new MaxPolicy();
    MaxPolicy policy =
      MaxPolicy(_deployPolicy(address(policyImpl), address(policyEngine), address(this), abi.encode(100)));
    MockTokenExtractor extractor = new MockTokenExtractor();

    bytes4[] memory selectors = new bytes4[](3);
    selectors[0] = MockToken.transfer.selector;
    selectors[1] = MockToken.transferWithContext.selector;
    selectors[2] = MockToken.transferFrom.selector;

    policyEngine.setExtractors(selectors, address(extractor));

    bytes32[] memory parameterOutputFormat = new bytes32[](1);
    parameterOutputFormat[0] = extractor.PARAM_AMOUNT();

    policyEngine.addPolicy(address(token), MockToken.transfer.selector, address(policy), parameterOutputFormat);
    policyEngine.addPolicy(
      address(token), MockToken.transferWithContext.selector, address(policy), parameterOutputFormat
    );
    policyEngine.addPolicy(address(token), MockToken.transferFrom.selector, address(policy), parameterOutputFormat);
  }

  function test_transfer_success() public {
    address recipient = makeAddr("recipient");
    token.transfer(recipient, 100);
    assert(token.balanceOf(recipient) == 100);
  }

  function test_transferWithContext_success() public {
    address recipient = makeAddr("recipient");
    token.transferWithContext(recipient, 100, "");
    assert(token.balanceOf(recipient) == 100);
  }

  function test_transfer_defaultPolicyRejected_reverts() public {
    policyEngine.setTargetDefaultPolicyResult(address(token), IPolicyEngine.PolicyResult.Rejected);

    address recipient = makeAddr("recipient");

    vm.expectPartialRevert(IPolicyEngine.PolicyRunRejected.selector);
    token.transfer(recipient, 100);
  }

  function test_transfer_overQuota_reverts() public {
    address recipient = makeAddr("recipient");
    vm.expectPartialRevert(IPolicyEngine.PolicyRunRejected.selector);
    token.transfer(recipient, 200);
  }

  function test_transferWithContext_overQuota_reverts() public {
    address recipient = makeAddr("recipient");
    vm.expectPartialRevert(IPolicyEngine.PolicyRunRejected.selector);
    token.transferWithContext(recipient, 200, "");
  }
}
