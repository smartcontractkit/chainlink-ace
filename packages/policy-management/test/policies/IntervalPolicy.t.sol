// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {IntervalPolicy} from "@chainlink/policy-management/policies/IntervalPolicy.sol";
import {MockToken} from "../helpers/MockToken.sol";
import {BaseProxyTest} from "../helpers/BaseProxyTest.sol";

contract IntervalPolicyTest is BaseProxyTest {
  PolicyEngine public policyEngine;
  IntervalPolicy public intervalPolicy;
  MockToken public token;
  address public deployer;
  address public recipient;
  uint256 public OFFSET_TIMESTAMP = 1737470407; // 	Tue Jan 21 2025 14:40:07

  function setUp() public {
    deployer = makeAddr("deployer");
    recipient = makeAddr("recipient");

    vm.startPrank(deployer);

    policyEngine = _deployPolicyEngine(IPolicyEngine.PolicyResult.Allowed, deployer);

    token = MockToken(_deployMockToken(address(policyEngine)));

    IntervalPolicy intervalPolicyImpl = new IntervalPolicy();
    bytes memory configParamBytes = abi.encode(
      11, // start slot
      17, // end slot
      1 hours, // slot duration
      24, // cycle size (24 slots for 24 hours)
      0 // cycle offset
    );
    intervalPolicy =
      IntervalPolicy(_deployPolicy(address(intervalPolicyImpl), address(policyEngine), deployer, configParamBytes));

    policyEngine.addPolicy(address(token), MockToken.transfer.selector, address(intervalPolicy), new bytes32[](0));
    vm.warp(OFFSET_TIMESTAMP);
  }

  function generateTimestampForTargetHour(uint256 targetHour) private view returns (uint256) {
    uint256 currentTimestamp = block.timestamp;
    uint256 currentHour = (currentTimestamp / 3600) % 24;
    if (targetHour > currentHour) {
      uint256 hoursToAdd = targetHour - currentHour;
      return currentTimestamp + (hoursToAdd * 3600);
    }

    uint256 hoursToDecrease = currentHour - targetHour;
    return currentTimestamp - (hoursToDecrease * 3600);
  }

  function generateTimestampForTargetDayAndHour(uint256 targetDay, uint256 targetHour) private view returns (uint256) {
    uint256 currentTimestamp = block.timestamp;
    uint256 timestampWithHour = generateTimestampForTargetHour(targetHour);
    uint256 currentDay = (currentTimestamp / 86400 + 4) % 7;
    uint256 daysToAdd = (targetDay + 7 - currentDay) % 7;
    uint256 newTimestamp = timestampWithHour + (daysToAdd * 86400);
    return newTimestamp;
  }

  function test_transfer_timeWithinInterval_succeeds() public {
    uint256 timestamp = generateTimestampForTargetHour(16);
    vm.warp(timestamp);
    token.transfer(recipient, 100);

    assert(token.balanceOf(recipient) == 100);
  }

  function test_transfer_timeExtractorExtractsTimeBelowLowerBoundInterval_reverts() public {
    uint256 timestamp = generateTimestampForTargetHour(10);
    vm.warp(timestamp);
    vm.expectPartialRevert(IPolicyEngine.PolicyRunRejected.selector);
    token.transfer(recipient, 100);
  }

  function test_transfer_timeExtractorExtractsTimeAboveUpperBoundInterval_reverts() public {
    uint256 timestamp = generateTimestampForTargetHour(18);
    vm.warp(timestamp);
    vm.expectPartialRevert(IPolicyEngine.PolicyRunRejected.selector);
    token.transfer(recipient, 100);
  }

  function test_transfer_timeExtractorWithTwoPoliciesExtractsTimeWithinInterval_succeeds() public {
    vm.startPrank(deployer);
    IntervalPolicy dayIntervalPolicyImpl = new IntervalPolicy();
    bytes memory configParamBytes = abi.encode(1, 6, 1 days, 7, 4);
    IntervalPolicy dayIntervalPolicy =
      IntervalPolicy(_deployPolicy(address(dayIntervalPolicyImpl), address(policyEngine), deployer, configParamBytes));
    policyEngine.addPolicy(address(token), MockToken.transfer.selector, address(dayIntervalPolicy), new bytes32[](0));

    uint256 timestamp = generateTimestampForTargetDayAndHour(2, 13);
    vm.warp(timestamp);
    token.transfer(recipient, 100);

    assert(token.balanceOf(recipient) == 100);
  }

  function test_transfer_timeExtractorWithTwoPoliciesHourBelowLowerBoundInterval_reverts() public {
    vm.startPrank(deployer);
    IntervalPolicy dayIntervalPolicyImpl = new IntervalPolicy();
    bytes memory configParamBytes = abi.encode(1, 6, 1 days, 7, 4);
    IntervalPolicy dayIntervalPolicy =
      IntervalPolicy(_deployPolicy(address(dayIntervalPolicyImpl), address(policyEngine), deployer, configParamBytes));
    policyEngine.addPolicy(address(token), MockToken.transfer.selector, address(dayIntervalPolicy), new bytes32[](0));

    uint256 timestamp = generateTimestampForTargetDayAndHour(2, 10);
    vm.warp(timestamp);
    vm.expectPartialRevert(IPolicyEngine.PolicyRunRejected.selector);
    token.transfer(recipient, 100);
  }

  function test_transfer_timeExtractorWithTwoPoliciesHourAboveUpperBoundInterval_reverts() public {
    vm.startPrank(deployer);
    IntervalPolicy dayIntervalPolicyImpl = new IntervalPolicy();
    bytes memory configParamBytes = abi.encode(1, 6, 1 days, 7, 4);
    IntervalPolicy dayIntervalPolicy =
      IntervalPolicy(_deployPolicy(address(dayIntervalPolicyImpl), address(policyEngine), deployer, configParamBytes));
    policyEngine.addPolicy(address(token), MockToken.transfer.selector, address(dayIntervalPolicy), new bytes32[](0));

    uint256 timestamp = generateTimestampForTargetDayAndHour(2, 18);
    vm.warp(timestamp);
    vm.expectPartialRevert(IPolicyEngine.PolicyRunRejected.selector);
    token.transfer(recipient, 100);
  }

  function test_transfer_timeExtractorWithTwoPoliciesDayBelowLowerBoundInterval_reverts() public {
    vm.startPrank(deployer);
    IntervalPolicy dayIntervalPolicyImpl = new IntervalPolicy();
    bytes memory configParamBytes = abi.encode(1, 6, 1 days, 7, 4);
    IntervalPolicy dayIntervalPolicy =
      IntervalPolicy(_deployPolicy(address(dayIntervalPolicyImpl), address(policyEngine), deployer, configParamBytes));
    policyEngine.addPolicy(address(token), MockToken.transfer.selector, address(dayIntervalPolicy), new bytes32[](0));

    uint256 timestamp = generateTimestampForTargetDayAndHour(0, 14);
    vm.warp(timestamp);
    vm.expectPartialRevert(IPolicyEngine.PolicyRunRejected.selector);
    token.transfer(recipient, 100);
  }

  function test_transfer_timeExtractorWithTwoPoliciesDayAboveUpperBoundInterval_reverts() public {
    vm.startPrank(deployer);
    IntervalPolicy dayIntervalPolicyImpl = new IntervalPolicy();
    bytes memory configParamBytes = abi.encode(1, 6, 1 days, 7, 4);
    IntervalPolicy dayIntervalPolicy =
      IntervalPolicy(_deployPolicy(address(dayIntervalPolicyImpl), address(policyEngine), deployer, configParamBytes));
    policyEngine.addPolicy(address(token), MockToken.transfer.selector, address(dayIntervalPolicy), new bytes32[](0));

    uint256 timestamp = generateTimestampForTargetDayAndHour(6, 14);
    vm.warp(timestamp);
    vm.expectPartialRevert(IPolicyEngine.PolicyRunRejected.selector);
    token.transfer(recipient, 100);
  }

  function test_setUpEndGreaterThanTimePeriodWindow_reverts() public {
    vm.startPrank(deployer);
    vm.expectRevert("End slot must be greater than start slot");
    intervalPolicy.setEndSlot(2);
  }

  function test_configure_emitsAllEvents() public {
    vm.startPrank(deployer);

    IntervalPolicy intervalPolicyImpl = new IntervalPolicy();
    bytes memory configParamBytes = abi.encode(
      5, // start slot
      15, // end slot
      2 hours, // slot duration
      24, // cycle size
      2 // cycle offset
    );

    vm.expectEmit(true, true, true, true);
    emit IntervalPolicy.StartSlotSet(5);
    vm.expectEmit(true, true, true, true);
    emit IntervalPolicy.EndSlotSet(15);
    vm.expectEmit(true, true, true, true);
    emit IntervalPolicy.CycleParametersSet(2 hours, 24, 2);

    IntervalPolicy(_deployPolicy(address(intervalPolicyImpl), address(policyEngine), deployer, configParamBytes));
  }

  function test_setStartSlot_emitsEvent() public {
    vm.startPrank(deployer);

    vm.expectEmit(true, true, true, true);
    emit IntervalPolicy.StartSlotSet(5);
    intervalPolicy.setStartSlot(5);

    assertEq(intervalPolicy.getStartSlot(), 5);
  }

  function test_setEndSlot_emitsEvent() public {
    vm.startPrank(deployer);

    vm.expectEmit(true, true, true, true);
    emit IntervalPolicy.EndSlotSet(20);
    intervalPolicy.setEndSlot(20);

    assertEq(intervalPolicy.getEndSlot(), 20);
  }

  function test_setCycleParameters_emitsEvent() public {
    vm.startPrank(deployer);

    intervalPolicy.setEndSlot(23);

    vm.expectEmit(true, true, true, true);
    emit IntervalPolicy.CycleParametersSet(30 minutes, 48, 5);
    intervalPolicy.setCycleParameters(30 minutes, 48, 5);

    (uint256 slotDuration, uint256 cycleSize, uint256 cycleOffset) = intervalPolicy.getCycleParameters();
    assertEq(slotDuration, 30 minutes);
    assertEq(cycleSize, 48);
    assertEq(cycleOffset, 5);
  }

  function test_canSetEndSlotEqualToCycleSize_succeeds() public {
    vm.startPrank(deployer);

    IntervalPolicy lastSlotPolicyImpl = new IntervalPolicy();
    bytes memory configParamBytes = abi.encode(5, 12, 1 hours, 12, 0);

    IntervalPolicy lastSlotPolicy =
      IntervalPolicy(_deployPolicy(address(lastSlotPolicyImpl), address(policyEngine), deployer, configParamBytes));

    assertEq(lastSlotPolicy.getStartSlot(), 5);
    assertEq(lastSlotPolicy.getEndSlot(), 12);
    (, uint256 cycleSize,) = lastSlotPolicy.getCycleParameters();
    assertEq(cycleSize, 12);
  }

  function test_firstSlotAndlastSlotExecution_succeds() public {
    vm.startPrank(deployer);

    policyEngine.removePolicy(address(token), MockToken.transfer.selector, address(intervalPolicy));

    IntervalPolicy lastSlotPolicyImpl = new IntervalPolicy();
    bytes memory configParamBytes = abi.encode(
      5, // start slot
      12, // end slot (equal to cycle size - now allowed)
      1 hours, // slot duration
      12, // cycle size
      0 // cycle offset
    );

    IntervalPolicy lastSlotPolicy =
      IntervalPolicy(_deployPolicy(address(lastSlotPolicyImpl), address(policyEngine), deployer, configParamBytes));

    assertEq(lastSlotPolicy.getStartSlot(), 5);
    assertEq(lastSlotPolicy.getEndSlot(), 12);
    (, uint256 cycleSize,) = lastSlotPolicy.getCycleParameters();
    assertEq(cycleSize, 12);

    policyEngine.addPolicy(address(token), MockToken.transfer.selector, address(lastSlotPolicy), new bytes32[](0));

    uint256 baseTimestamp = (12 * 3600);

    uint256 slot5Timestamp = baseTimestamp + (5 * 3600);
    vm.warp(slot5Timestamp);

    token.transfer(recipient, 50);
    assertEq(token.balanceOf(recipient), 50);

    uint256 slot4Timestamp = baseTimestamp + (4 * 3600);
    vm.warp(slot4Timestamp);

    vm.expectPartialRevert(IPolicyEngine.PolicyRunRejected.selector);
    token.transfer(recipient, 25);

    uint256 slot11Timestamp = baseTimestamp + (11 * 3600);
    vm.warp(slot11Timestamp);

    token.transfer(recipient, 100);
    assertEq(token.balanceOf(recipient), 150);
  }
}
