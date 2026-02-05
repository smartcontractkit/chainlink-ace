// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IPolicyEngine, PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {PausePolicy} from "@chainlink/policy-management/policies/PausePolicy.sol";
import {MockTokenUpgradeable} from "../helpers/MockTokenUpgradeable.sol";
import {BaseProxyTest} from "../helpers/BaseProxyTest.sol";

contract PausePolicyTest is BaseProxyTest {
  PolicyEngine public policyEngine;
  MockTokenUpgradeable public token;
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
    pausePolicy = PausePolicy(
      _deployPolicy(address(pausePolicyImpl), address(policyEngine), address(policyEngine), configParamBytes)
    );

    token = MockTokenUpgradeable(_deployMockToken(address(policyEngine)));

    policyEngine.addPolicy(
      address(token), MockTokenUpgradeable.transfer.selector, address(pausePolicy), new bytes32[](0)
    );
  }

  function test_transfer_whenPaused_reverts() public {
    vm.startPrank(deployer);

    policyEngine.setPolicyConfiguration(address(pausePolicy), 0, PausePolicy.setPausedState.selector, abi.encode(true));

    _expectRejectedRevert(
      address(pausePolicy),
      "contract is paused",
      MockTokenUpgradeable.transfer.selector,
      deployer,
      abi.encode(recipient, 100)
    );
    token.transfer(recipient, 100);
  }

  function test_transfer_whenNotPaused_succeeds() public {
    token.transfer(recipient, 100);
    assert(token.balanceOf(recipient) == 100);
  }

  function test_transfer_afterUnpause_succeeds() public {
    vm.startPrank(deployer);

    vm.expectEmit(true, true, true, true);
    emit PausePolicy.PauseStateChanged(true);

    policyEngine.setPolicyConfiguration(address(pausePolicy), 0, PausePolicy.setPausedState.selector, abi.encode(true));
    assert(pausePolicy.s_paused() == true);

    vm.expectEmit(true, true, true, true);
    emit PausePolicy.PauseStateChanged(false);

    policyEngine.setPolicyConfiguration(address(pausePolicy), 1, PausePolicy.setPausedState.selector, abi.encode(false));

    token.transfer(recipient, 100);
    assert(token.balanceOf(recipient) == 100);
  }

  function test_pause_whenAlreadyPaused_reverts() public {
    vm.startPrank(deployer);

    policyEngine.setPolicyConfiguration(address(pausePolicy), 0, PausePolicy.setPausedState.selector, abi.encode(true));
    assert(pausePolicy.s_paused() == true);

    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyConfigurationError.selector,
        address(pausePolicy),
        abi.encodeWithSignature("Error(string)", "new paused state must be different from current paused state")
      )
    );
    policyEngine.setPolicyConfiguration(address(pausePolicy), 1, PausePolicy.setPausedState.selector, abi.encode(true));
  }

  function test_unpause_whenAlreadyUnpaused_reverts() public {
    vm.startPrank(deployer);

    assert(pausePolicy.s_paused() == false);

    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyConfigurationError.selector,
        address(pausePolicy),
        abi.encodeWithSignature("Error(string)", "new paused state must be different from current paused state")
      )
    );
    policyEngine.setPolicyConfiguration(address(pausePolicy), 0, PausePolicy.setPausedState.selector, abi.encode(false));
  }
}
