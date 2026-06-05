// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IPolicyEngine} from "../../src/interfaces/IPolicyEngine.sol";
import {PolicyEngine} from "../../src/core/PolicyEngine.sol";
import {VolumeRatePolicy} from "../../src/policies/VolumeRatePolicy.sol";
import {ERC20TransferExtractor} from "../../src/extractors/ERC20TransferExtractor.sol";
import {ERC3643MintBurnExtractor} from "../../src/extractors/ERC3643MintBurnExtractor.sol";
import {MockTokenUpgradeable} from "../helpers/MockTokenUpgradeable.sol";
import {BaseProxyTest} from "../helpers/BaseProxyTest.sol";

contract VolumeRatePolicyTest is BaseProxyTest {
  PolicyEngine public policyEngine;
  VolumeRatePolicy public volumeRatePolicy;
  ERC20TransferExtractor public extractor;
  MockTokenUpgradeable token;
  address public deployer;
  address public txSender;

  function setUp() public {
    deployer = makeAddr("deployer");
    txSender = makeAddr("txSender");

    vm.startPrank(deployer);

    policyEngine = _deployPolicyEngine(true, deployer);

    token = MockTokenUpgradeable(_deployMockToken(address(policyEngine)));

    extractor = new ERC20TransferExtractor();
    bytes32[] memory parameterOutputFormat = new bytes32[](2);
    parameterOutputFormat[0] = extractor.PARAM_AMOUNT();
    parameterOutputFormat[1] = extractor.PARAM_FROM();

    VolumeRatePolicy volumeRatePolicyImpl = new VolumeRatePolicy();
    volumeRatePolicy = VolumeRatePolicy(
      _deployPolicy(address(volumeRatePolicyImpl), address(policyEngine), deployer, abi.encode(1 days, 200))
    );

    policyEngine.setExtractor(MockTokenUpgradeable.transfer.selector, address(extractor));

    policyEngine.addPolicy(
      address(token), MockTokenUpgradeable.transfer.selector, address(volumeRatePolicy), parameterOutputFormat
    );
    vm.warp(1737583804);
  }

  function test_setTimePeriodDuration_succeeds() public {
    vm.startPrank(deployer, deployer);

    vm.expectEmit();
    emit VolumeRatePolicy.TimePeriodDurationSet(2 days);
    volumeRatePolicy.setTimePeriodDuration(2 days);
    vm.assertEq(volumeRatePolicy.getTimePeriodDuration(), 2 days);
  }

  function test_setTimePeriodDuration_sameAmount_fails() public {
    vm.startPrank(deployer, deployer);

    vm.expectRevert("new duration same as current duration");
    volumeRatePolicy.setTimePeriodDuration(1 days);
  }

  function test_setMaxAmount_succeeds() public {
    vm.startPrank(deployer, deployer);

    vm.expectEmit();
    emit VolumeRatePolicy.MaxAmountSet(999);
    volumeRatePolicy.setMaxAmount(999);
    vm.assertEq(volumeRatePolicy.getMaxAmount(), 999);
  }

  function test_setMaxAmount_sameAmount_fails() public {
    vm.startPrank(deployer, deployer);

    vm.expectRevert("new max amount same as current max amount");
    volumeRatePolicy.setMaxAmount(200);
  }

  function test_transfer_volumeBelowMaxAllowed_succeeds() public {
    address recipient = makeAddr("recipient");

    vm.startPrank(txSender);

    token.transfer(recipient, 100);

    assert(token.balanceOf(recipient) == 100);
  }

  function test_transfer_volumeAboveMaxAllowed_fails() public {
    address recipient = makeAddr("recipient");

    vm.startPrank(txSender);

    token.transfer(recipient, 100);

    _expectRejectedRevert(
      address(volumeRatePolicy),
      "volume rate limit exceeded for time period",
      MockTokenUpgradeable.transfer.selector,
      txSender,
      abi.encode(recipient, 101)
    );
    token.transfer(recipient, 101);

    assert(token.balanceOf(recipient) == 100);
  }

  function test_transfer_volumeBelowMaxAllowedMultipleTimes_succeeds() public {
    address recipient = makeAddr("recipient");

    vm.startPrank(txSender);

    token.transfer(recipient, 100);
    token.transfer(recipient, 50);
    token.transfer(recipient, 49);

    assert(token.balanceOf(recipient) == 199);
  }

  function test_transfer_volumeTrackingResetsAfterDurationChange_succeeds() public {
    address recipient = makeAddr("recipient");

    vm.startPrank(txSender);

    token.transfer(recipient, 100);
    vm.warp(block.timestamp + 1 days);

    token.transfer(recipient, 200);
    assert(token.balanceOf(recipient) == 300);

    _expectRejectedRevert(
      address(volumeRatePolicy),
      "volume rate limit exceeded for time period",
      MockTokenUpgradeable.transfer.selector,
      txSender,
      abi.encode(recipient, 1)
    );
    token.transfer(recipient, 1);
  }

  function test_transfer_sameTimePeriodAfterDurationChange_succeeds() public {
    address recipient = makeAddr("recipient");

    vm.startPrank(txSender);
    vm.warp(1000 days);

    // first transfer at time period 1000 (succeeds)
    token.transfer(recipient, 200);
    vm.assertEq(token.balanceOf(recipient), 200);

    // second transfer at time period 1000 (fails)
    _expectRejectedRevert(
      address(volumeRatePolicy),
      "volume rate limit exceeded for time period",
      MockTokenUpgradeable.transfer.selector,
      txSender,
      abi.encode(recipient, 200)
    );
    token.transfer(recipient, 200);

    // change time period duration to 2 days and wrap to 2000 days
    vm.startPrank(deployer);
    volumeRatePolicy.setTimePeriodDuration(2 days);
    vm.warp(2000 days);

    // third transfer at time period 1000 (succeeds)
    vm.startPrank(txSender);
    token.transfer(recipient, 200);
    vm.assertEq(token.balanceOf(recipient), 400);
  }

  function test_misconfiguration_failure() public {
    vm.startPrank(deployer);
    ERC3643MintBurnExtractor mintBurnExtractor = new ERC3643MintBurnExtractor();
    policyEngine.setExtractor(MockTokenUpgradeable.burn.selector, address(mintBurnExtractor));
    policyEngine.addPolicy(
      address(token), MockTokenUpgradeable.burn.selector, address(volumeRatePolicy), new bytes32[](0)
    );

    IPolicyEngine.Payload memory payload = IPolicyEngine.Payload({
      selector: MockTokenUpgradeable.burn.selector,
      sender: deployer,
      data: abi.encode(txSender, 100),
      context: new bytes(0)
    });
    bytes memory error = abi.encodeWithSignature("InvalidParameters(string)", "expected 2 parameters");
    _expectRunError(address(volumeRatePolicy), error, payload);
    token.burn(txSender, 100);
  }
}
