// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {VolumePolicy} from "@chainlink/policy-management/policies/VolumePolicy.sol";
import {ERC20TransferValueExtractor} from "@chainlink/policy-management/extractors/ERC20TransferValueExtractor.sol";
import {MockToken} from "../helpers/MockToken.sol";
import {MockAggregatorV3} from "../helpers/MockAggregatorV3.sol";
import {BaseProxyTest} from "../helpers/BaseProxyTest.sol";

contract VolumePolicyTest is BaseProxyTest {
  PolicyEngine public policyEngine;
  VolumePolicy public volumePolicy;
  ERC20TransferValueExtractor public extractor;
  MockAggregatorV3 public priceFeed;
  MockToken public token;
  address public deployer;
  address public txSender;

  uint8 public constant PRICE_FEED_DECIMALS = 8;
  uint256 public constant PRICE_FEED_PRICE = 3500;
  uint8 public constant TOKEN_DECIMALS = 18;

  function setUp() public {
    deployer = makeAddr("deployer");
    txSender = makeAddr("txSender");

    vm.startPrank(deployer);

    policyEngine = _deployPolicyEngine(IPolicyEngine.PolicyResult.Allowed, deployer);

    token = MockToken(_deployMockToken(address(policyEngine)));

    extractor = new ERC20TransferValueExtractor(address(0));
    bytes32[] memory parameterOutputFormat = new bytes32[](1);
    parameterOutputFormat[0] = extractor.PARAM_AMOUNT();

    VolumePolicy volumePolicyImpl = new VolumePolicy();
    volumePolicy =
      VolumePolicy(_deployPolicy(address(volumePolicyImpl), address(policyEngine), deployer, abi.encode(100, 200)));

    policyEngine.setExtractor(MockToken.transfer.selector, address(extractor));

    policyEngine.addPolicy(address(token), MockToken.transfer.selector, address(volumePolicy), parameterOutputFormat);

    priceFeed = new MockAggregatorV3(int256(PRICE_FEED_PRICE * 10 ** PRICE_FEED_DECIMALS), PRICE_FEED_DECIMALS);
  }

  function test_policy_initMaxBelowMin_fails() public {
    vm.startPrank(deployer);
    VolumePolicy invalidVolumePolicyImpl = new VolumePolicy();
    vm.expectRevert("maxAmount must be greater than minAmount");
    _deployPolicy(address(invalidVolumePolicyImpl), address(policyEngine), deployer, abi.encode(200, 100));
  }

  function test_policy_initMaxEqualsMin_fails() public {
    vm.startPrank(deployer);
    VolumePolicy invalidVolumePolicyImpl = new VolumePolicy();
    vm.expectRevert("maxAmount must be greater than minAmount");
    _deployPolicy(address(invalidVolumePolicyImpl), address(policyEngine), deployer, abi.encode(200, 200));
  }

  function test_setMax_succeeds() public {
    vm.startPrank(deployer, deployer);

    // Set the max amount to 100
    vm.expectEmit();
    emit VolumePolicy.MaxVolumeSet(150);
    volumePolicy.setMax(150);
    vm.assertEq(volumePolicy.getMax(), 150);
  }

  function test_setMax_sameAsCurrent_fails() public {
    vm.startPrank(deployer, deployer);

    // Set the max amount to 100 (sanity check)
    vm.expectEmit();
    emit VolumePolicy.MaxVolumeSet(150);
    volumePolicy.setMax(150);
    vm.assertEq(volumePolicy.getMax(), 150);

    // Set the max amount to 100 again (revert)
    vm.expectRevert("maxAmount cannot be the same as current maxAmount");
    volumePolicy.setMax(150);
  }

  function test_setMin_succeeds() public {
    vm.startPrank(deployer, deployer);

    // Set the min amount to 1
    vm.expectEmit();
    emit VolumePolicy.MinVolumeSet(1);
    volumePolicy.setMin(1);
    vm.assertEq(volumePolicy.getMin(), 1);
  }

  function test_setMin_sameAsCurrent_fails() public {
    vm.startPrank(deployer, deployer);

    // Set the min amount to 1 (sanity check)
    vm.expectEmit();
    emit VolumePolicy.MinVolumeSet(1);
    volumePolicy.setMin(1);
    vm.assertEq(volumePolicy.getMin(), 1);

    // Set the min amount to 1 again (revert)
    vm.expectRevert("minAmount cannot be the same as current minAmount");
    volumePolicy.setMin(1);
  }

  function test_transfer_extractorWithoutPriceFeedAndAmountBelowMaxVolumePolicy_succeeds() public {
    address recipient = makeAddr("recipient");

    vm.startPrank(txSender);

    token.transfer(recipient, 199);

    assert(token.balanceOf(recipient) == 199);
  }

  function test_transfer_extractorWithoutPriceFeedAndAmountAboveMaxVolumePolicy_reverts() public {
    address recipient = makeAddr("recipient");

    vm.startPrank(txSender);

    vm.expectPartialRevert(IPolicyEngine.PolicyRunRejected.selector);

    token.transfer(recipient, 201);
  }

  function test_transfer_extractorWithoutPriceAndAmountAboveMinVolumePolicy_succeeds() public {
    address recipient = makeAddr("recipient");

    vm.startPrank(txSender);

    token.transfer(recipient, 101);

    assert(token.balanceOf(recipient) == 101);
  }

  function test_transfer_extractorWithoutPriceAndAmountBelowMinVolumePolicy_reverts() public {
    address recipient = makeAddr("recipient");

    vm.startPrank(txSender);

    vm.expectPartialRevert(IPolicyEngine.PolicyRunRejected.selector);

    token.transfer(recipient, 99);
  }

  function test_transfer_setMaxBelowMinVolumePolicy_reverts() public {
    vm.expectRevert("maxAmount must be greater than minAmount");
    volumePolicy.setMax(99);
  }

  function test_transfer_setMinAboveMaxVolumePolicy_reverts() public {
    vm.expectRevert("minAmount must be less than maxAmount");

    volumePolicy.setMin(201);
  }

  function test_transfer_withPriceFeedAndAmountBelowMaxVolumePolicy_succeeds() public {
    vm.startPrank(deployer);
    volumePolicy.setMax(PRICE_FEED_PRICE * 3 * 10 ** TOKEN_DECIMALS);
    extractor.setPriceFeed(address(priceFeed));

    address recipient = makeAddr("recipient");

    vm.startPrank(txSender);

    token.transfer(recipient, 2 * 10 ** TOKEN_DECIMALS);

    assert(token.balanceOf(recipient) == 2 * 10 ** TOKEN_DECIMALS);
  }

  function test_transfer_withPriceFeedAndAmountAboveMaxVolumePolicy_reverts() public {
    vm.startPrank(deployer);
    volumePolicy.setMax(PRICE_FEED_PRICE * 3 * 10 ** TOKEN_DECIMALS);
    extractor.setPriceFeed(address(priceFeed));

    address recipient = makeAddr("recipient");

    vm.startPrank(txSender);

    vm.expectPartialRevert(IPolicyEngine.PolicyRunRejected.selector);

    token.transfer(recipient, 4 * 10 ** TOKEN_DECIMALS);
  }

  function test_transfer_withPriceFeedAnAmountAboveMinVolumePolicy_succeeds() public {
    vm.startPrank(deployer);
    volumePolicy.setMax(0);
    volumePolicy.setMin(PRICE_FEED_PRICE * 3 * 10 ** TOKEN_DECIMALS);
    extractor.setPriceFeed(address(priceFeed));

    address recipient = makeAddr("recipient");

    vm.startPrank(txSender);

    token.transfer(recipient, 4 * 10 ** TOKEN_DECIMALS);

    assert(token.balanceOf(recipient) == 4 * 10 ** TOKEN_DECIMALS);
  }

  function test_transfer_withPriceFeedAnAmountBelowMinVolumePolicy_reverts() public {
    vm.startPrank(deployer);
    volumePolicy.setMax(0);
    volumePolicy.setMin(PRICE_FEED_PRICE * 3 * 10 ** TOKEN_DECIMALS);
    extractor.setPriceFeed(address(priceFeed));

    address recipient = makeAddr("recipient");

    vm.startPrank(txSender);

    vm.expectPartialRevert(IPolicyEngine.PolicyRunRejected.selector);

    token.transfer(recipient, 2 * 10 ** TOKEN_DECIMALS);
  }
}
