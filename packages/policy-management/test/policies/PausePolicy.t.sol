// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IPolicyEngine, PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {PausePolicy} from "@chainlink/policy-management/policies/PausePolicy.sol";
import {MockToken} from "../helpers/MockToken.sol";
import {BaseProxyTest} from "../helpers/BaseProxyTest.sol";

contract PausePolicyTest is BaseProxyTest {
  PolicyEngine public policyEngine;
  MockToken public token;
  PausePolicy public pausePolicy;
  address public deployer;
  address public recipient;

  function setUp() public {
    deployer = makeAddr("deployer");
    recipient = makeAddr("recipient");

    vm.startPrank(deployer);

    policyEngine = _deployPolicyEngine(true, deployer);

    PausePolicy pausePolicyImpl = new PausePolicy();
    bytes memory configParamBytes = abi.encode(false); // Initial paused state is false
    pausePolicy =
      PausePolicy(_deployPolicy(address(pausePolicyImpl), address(policyEngine), deployer, configParamBytes));

    token = MockToken(_deployMockToken(address(policyEngine)));

    policyEngine.addPolicy(address(token), MockToken.transfer.selector, address(pausePolicy), new bytes32[](0));
  }

  function test_transfer_whenPaused_reverts() public {
    vm.startPrank(deployer);
    pausePolicy.pause();

    vm.expectRevert(_encodeRejectedRevert(MockToken.transfer.selector, address(pausePolicy), "contract is paused"));
    token.transfer(recipient, 100);
  }

  function test_transfer_whenNotPaused_succeeds() public {
    token.transfer(recipient, 100);
    assert(token.balanceOf(recipient) == 100);
  }

  function test_transfer_afterUnpause_succeeds() public {
    vm.startPrank(deployer);
    pausePolicy.pause();
    assert(pausePolicy.s_paused() == true);
    pausePolicy.unpause();

    token.transfer(recipient, 100);
    assert(token.balanceOf(recipient) == 100);
  }

  function test_pause_whenAlreadyPaused_reverts() public {
    vm.startPrank(deployer);

    pausePolicy.pause();
    assert(pausePolicy.s_paused() == true);

    vm.expectRevert("already paused");
    pausePolicy.pause();
  }

  function test_unpause_whenAlreadyUnpaused_reverts() public {
    vm.startPrank(deployer);

    assert(pausePolicy.s_paused() == false);

    vm.expectRevert("already unpaused");
    pausePolicy.unpause();
  }
}
