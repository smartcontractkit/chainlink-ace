// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Vm} from "forge-std/Vm.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {ERC3643MintBurnExtractor} from "@chainlink/policy-management/extractors/ERC3643MintBurnExtractor.sol";
import {SecureMintPolicy} from "@chainlink/policy-management/policies/SecureMintPolicy.sol";
import {MockTokenUpgradeable} from "../helpers/MockTokenUpgradeable.sol";
import {MockAggregatorV3} from "../helpers/MockAggregatorV3.sol";
import {BaseProxyTest} from "../helpers/BaseProxyTest.sol";

contract TokenWithoutDecimals {
  function totalSupply() external pure returns (uint256) {
    return 0;
  }
}

contract SecureMintPolicyTest is BaseProxyTest {
  uint8 private constant TOKEN_DECIMALS = 18;
  uint8 private constant POR_FEED_DECIMALS = 18;
  PolicyEngine public policyEngine;
  SecureMintPolicy public policy;
  ERC3643MintBurnExtractor public extractor;
  MockTokenUpgradeable public token;
  MockAggregatorV3 public porFeed;
  address public deployer;
  address public recipient;

  function setUp() public {
    deployer = makeAddr("deployer");
    recipient = makeAddr("recipient");

    vm.startPrank(deployer, deployer);

    policyEngine = _deployPolicyEngine(true, deployer);

    token = MockTokenUpgradeable(_deployMockToken(address(policyEngine)));

    porFeed = new MockAggregatorV3(42 ether, POR_FEED_DECIMALS);

    extractor = new ERC3643MintBurnExtractor();
    bytes32[] memory parameterOutputFormat = new bytes32[](1);
    parameterOutputFormat[0] = extractor.PARAM_AMOUNT();

    SecureMintPolicy policyImpl = new SecureMintPolicy();
    policy = SecureMintPolicy(
      _deployPolicy(
        address(policyImpl),
        address(policyEngine),
        deployer,
        abi.encode(
          address(porFeed),
          SecureMintPolicy.ReserveMarginConfigs({
            reserveMarginMode: SecureMintPolicy.ReserveMarginMode.None,
            reserveMarginAmount: 0
          }),
          0,
          SecureMintPolicy.TokenMetadata(address(token), TOKEN_DECIMALS)
        )
      )
    );

    policyEngine.setExtractor(MockTokenUpgradeable.mint.selector, address(extractor));
    policyEngine.addPolicy(address(token), MockTokenUpgradeable.mint.selector, address(policy), parameterOutputFormat);

    vm.warp(1737583804);
  }

  function test_initialize_configEvents_succeeds() public {
    SecureMintPolicy policyImpl = new SecureMintPolicy();

    // Set the reserves feed to a new address
    vm.expectEmit();
    emit SecureMintPolicy.ReservesFeedSet(address(porFeed));
    vm.expectEmit();
    emit SecureMintPolicy.ReserveMarginSet(SecureMintPolicy.ReserveMarginMode.None, 0);
    vm.expectEmit();
    emit SecureMintPolicy.MaxStalenessSecondsSet(600);
    vm.expectEmit();
    emit SecureMintPolicy.TokenMetadataSet(address(token), TOKEN_DECIMALS);
    policy = SecureMintPolicy(
      _deployPolicy(
        address(policyImpl),
        address(policyEngine),
        deployer,
        abi.encode(
          address(porFeed),
          SecureMintPolicy.ReserveMarginConfigs({
            reserveMarginMode: SecureMintPolicy.ReserveMarginMode.None,
            reserveMarginAmount: 0
          }),
          600,
          SecureMintPolicy.TokenMetadata(address(token), TOKEN_DECIMALS)
        )
      )
    );
  }

  function test_setReservesFeed_succeeds() public {
    MockAggregatorV3 newPorFeed = new MockAggregatorV3(42 ether, 18);

    vm.startPrank(deployer, deployer);

    // Set the reserves feed to a new address
    vm.expectEmit();
    emit SecureMintPolicy.ReservesFeedSet(address(newPorFeed));
    policy.setReservesFeed(address(newPorFeed));
    vm.assertEq(address(policy.reservesFeed()), address(newPorFeed));
  }

  function test_setReservesFeed_notOwner_reverts() public {
    MockAggregatorV3 newPorFeed = new MockAggregatorV3(42 ether, 18);

    vm.startPrank(recipient, recipient);

    vm.expectPartialRevert(OwnableUpgradeable.OwnableUnauthorizedAccount.selector);
    policy.setReservesFeed(address(newPorFeed));
  }

  function test_setReservesFeed_sameAsCurrent_reverts() public {
    vm.startPrank(deployer, deployer);

    // Set the reserves feed to the same address
    vm.expectRevert("feed same as current");
    policy.setReservesFeed(address(porFeed));
  }

  function test_setTokenDecimals_succeeds() public {
    uint8 newDecimals = 6;

    vm.startPrank(deployer, deployer);

    vm.recordLogs();
    policy.setTokenMetadata(address(token), newDecimals);
    Vm.Log[] memory entries = vm.getRecordedLogs();
    assertEq(entries.length, 1, "unexpected log count");
    assertEq(entries[0].topics[0], keccak256("TokenMetadataSet(address,uint8)"));
    (address loggedToken, uint8 loggedDecimals) = abi.decode(entries[0].data, (address, uint8));
    assertEq(loggedToken, address(token));
    assertEq(loggedDecimals, newDecimals);

    bytes[] memory parameters = new bytes[](1);
    parameters[0] = abi.encode(uint256(42 * (10 ** uint256(newDecimals))));
    IPolicyEngine.PolicyResult result =
      policy.run(deployer, address(token), MockTokenUpgradeable.mint.selector, parameters, bytes(""));
    assertEq(uint256(result), uint256(IPolicyEngine.PolicyResult.Continue));

    parameters[0] = abi.encode(uint256(42 * (10 ** uint256(newDecimals)) + 1));
    vm.expectRevert(
      abi.encodeWithSelector(IPolicyEngine.PolicyRejected.selector, "mint would exceed available reserves")
    );
    policy.run(deployer, address(token), MockTokenUpgradeable.mint.selector, parameters, bytes(""));
  }

  function test_setTokenDecimals_notOwner_reverts() public {
    vm.startPrank(recipient, recipient);

    vm.expectPartialRevert(OwnableUpgradeable.OwnableUnauthorizedAccount.selector);
    policy.setTokenMetadata(address(token), 6);
  }

  function test_setTokenDecimals_tokenWithoutDecimalsInterface_succeeds() public {
    TokenWithoutDecimals tokenWithoutDecimals = new TokenWithoutDecimals();

    SecureMintPolicy policyImpl = new SecureMintPolicy();
    SecureMintPolicy localPolicy = SecureMintPolicy(
      _deployPolicy(
        address(policyImpl),
        address(policyEngine),
        deployer,
        abi.encode(
          address(porFeed),
          SecureMintPolicy.ReserveMarginMode.None,
          0,
          0,
          SecureMintPolicy.TokenMetadata(address(tokenWithoutDecimals), TOKEN_DECIMALS)
        )
      )
    );

    vm.startPrank(deployer, deployer);

    vm.recordLogs();
    localPolicy.setTokenMetadata(address(tokenWithoutDecimals), 6);
    Vm.Log[] memory entries = vm.getRecordedLogs();
    assertEq(entries.length, 1, "unexpected log count");
    assertEq(entries[0].topics[0], keccak256("TokenMetadataSet(address,uint8)"));
    (address loggedToken, uint8 loggedDecimals) = abi.decode(entries[0].data, (address, uint8));
    assertEq(loggedToken, address(tokenWithoutDecimals));
    assertEq(loggedDecimals, 6);

    vm.stopPrank();
  }

  function test_setTokenDecimals_tokenAddressMismatch_reverts() public {
    vm.startPrank(deployer, deployer);
    vm.expectRevert("token address mismatch");
    policy.setTokenMetadata(makeAddr("wrong"), 6);
    vm.stopPrank();
  }

  function test_setTokenDecimals_sameAsCurrent_reverts() public {
    vm.startPrank(deployer, deployer);
    vm.expectRevert("decimals same as current");
    policy.setTokenMetadata(address(token), TOKEN_DECIMALS);
    vm.stopPrank();
  }

  function test_setTokenDecimals_zeroDecimals_reverts() public {
    vm.startPrank(deployer, deployer);
    vm.expectRevert("decimals must be > 0");
    policy.setTokenMetadata(address(token), 0);
    vm.stopPrank();
  }

  function test_setTokenDecimals_tokenMetadataMismatch_reverts() public {
    vm.mockCall(address(token), abi.encodeWithSelector(IERC20Metadata.decimals.selector), abi.encode(uint8(7)));

    vm.startPrank(deployer, deployer);
    vm.expectRevert("decimals mismatch with token metadata");
    policy.setTokenMetadata(address(token), 6);
    vm.stopPrank();

    vm.clearMockedCalls();
  }

  function test_setReserveMargin_succeeds() public {
    vm.startPrank(deployer, deployer);

    vm.expectEmit();
    emit SecureMintPolicy.ReserveMarginSet(SecureMintPolicy.ReserveMarginMode.PositivePercentage, 1000);
    policy.setReserveMargin(SecureMintPolicy.ReserveMarginMode.PositivePercentage, 1000);
    assertEq(uint256(policy.reserveMarginMode()), 1);
    assertEq(policy.reserveMarginAmount(), 1000);
  }

  function test_setReserveMargin_notOwner_reverts() public {
    vm.startPrank(recipient, recipient);

    vm.expectPartialRevert(OwnableUpgradeable.OwnableUnauthorizedAccount.selector);
    policy.setReserveMargin(SecureMintPolicy.ReserveMarginMode.PositivePercentage, 1000);
  }

  function test_setReserveMargin_sameAsCurrent_reverts() public {
    vm.startPrank(deployer, deployer);

    vm.expectRevert("margin same as current");
    policy.setReserveMargin(SecureMintPolicy.ReserveMarginMode.None, 0);
  }

  function test_setReserveMargin_positivePercentageExceedsMax_reverts() public {
    vm.startPrank(deployer, deployer);

    vm.expectRevert("margin must be <= BASIS_POINTS for percentage modes");
    policy.setReserveMargin(SecureMintPolicy.ReserveMarginMode.PositivePercentage, 10001);
  }

  function test_setReserveMargin_negativePercentageExceedsMax_reverts() public {
    vm.startPrank(deployer, deployer);

    vm.expectRevert("margin must be <= BASIS_POINTS for percentage modes");
    policy.setReserveMargin(SecureMintPolicy.ReserveMarginMode.NegativePercentage, 10001);
  }

  function test_setReserveMargin_positiveAbsoluteZeroAmount_reverts() public {
    vm.startPrank(deployer, deployer);

    vm.expectRevert("margin must be > 0 for absolute modes");
    policy.setReserveMargin(SecureMintPolicy.ReserveMarginMode.PositiveAbsolute, 0);
  }

  function test_setReserveMargin_negativeAbsoluteZeroAmount_reverts() public {
    vm.startPrank(deployer, deployer);

    vm.expectRevert("margin must be > 0 for absolute modes");
    policy.setReserveMargin(SecureMintPolicy.ReserveMarginMode.NegativeAbsolute, 0);
  }

  function test_setMaxStalenessSeconds_succeeds() public {
    vm.startPrank(deployer, deployer);

    vm.expectEmit();
    emit SecureMintPolicy.MaxStalenessSecondsSet(600);
    policy.setMaxStalenessSeconds(600);
    assertEq(policy.maxStalenessSeconds(), 600);
  }

  function test_setMaxStalenessSeconds_notOwner_reverts() public {
    vm.startPrank(recipient, recipient);

    vm.expectPartialRevert(OwnableUpgradeable.OwnableUnauthorizedAccount.selector);
    policy.setMaxStalenessSeconds(600);
  }

  function test_setMaxStalenessSeconds_sameAsCurrent_reverts() public {
    vm.startPrank(deployer, deployer);

    vm.expectRevert("value same as current");
    policy.setMaxStalenessSeconds(0);
  }

  function test_mint_marginModeNone_succeeds() public {
    vm.startPrank(deployer, deployer);

    // 0 + 40 <= 42, succeeds
    token.mint(recipient, 40 ether);
    assertEq(token.balanceOf(recipient), 40 ether);

    // 40 + 2 <= 42, succeeds
    token.mint(recipient, 2 ether);
    assertEq(token.balanceOf(recipient), 42 ether);
  }

  function test_mint_marginModeNone_reverts() public {
    vm.startPrank(deployer, deployer);

    // 0 + 40 <= 42, succeeds
    token.mint(recipient, 40 ether);
    assertEq(token.balanceOf(recipient), 40 ether);

    // 40 + 3 > 42, reverts
    _expectRejectedRevert(
      address(policy),
      "mint would exceed available reserves",
      MockTokenUpgradeable.mint.selector,
      deployer,
      abi.encode(recipient, 3 ether)
    );
    token.mint(recipient, 3 ether);

    // 40 + 2 <= 42, succeeds
    token.mint(recipient, 2 ether);
    assertEq(token.balanceOf(recipient), 42 ether);
  }

  function test_mint_marginModePositivePercentage_succeeds() public {
    vm.startPrank(deployer, deployer);

    // set margin (mintable amount = 42 ether * (1 - 20%) = 33.6 ether)
    policy.setReserveMargin(SecureMintPolicy.ReserveMarginMode.PositivePercentage, 2000); // 20%

    // 0 + 30 <= 33.6, succeeds
    token.mint(recipient, 30 ether);
    assertEq(token.balanceOf(recipient), 30 ether);

    // 30 + 3.6 <= 33.6, succeeds
    token.mint(recipient, 3.6 ether);
    assertEq(token.balanceOf(recipient), 33.6 ether);
  }

  function test_mint_marginModePositivePercentage100_reverts() public {
    vm.startPrank(deployer, deployer);

    // set margin (mintable amount = 42 ether * (1 - 100%) = 0 ether)
    policy.setReserveMargin(SecureMintPolicy.ReserveMarginMode.PositivePercentage, 10000); // 100%

    // 0 + 0.1 > 0, reverts
    _expectRejectedRevert(
      address(policy),
      "mint would exceed available reserves",
      MockTokenUpgradeable.mint.selector,
      deployer,
      abi.encode(recipient, 0.1 ether)
    );
    token.mint(recipient, 0.1 ether);
  }

  function test_mint_marginModePositivePercentage_reverts() public {
    vm.startPrank(deployer, deployer);

    // set margin (mintable amount = 42 ether * (1 - 20%) = 33.6 ether)
    policy.setReserveMargin(SecureMintPolicy.ReserveMarginMode.PositivePercentage, 2000); // 20%

    // 0 + 30 <= 33.6, succeeds
    token.mint(recipient, 30 ether);
    assertEq(token.balanceOf(recipient), 30 ether);

    // 30 + 4 > 33.6, reverts
    _expectRejectedRevert(
      address(policy),
      "mint would exceed available reserves",
      MockTokenUpgradeable.mint.selector,
      deployer,
      abi.encode(recipient, 4 ether)
    );
    token.mint(recipient, 4 ether);

    // 30 + 3 <= 33.6, succeeds
    token.mint(recipient, 3 ether);
    assertEq(token.balanceOf(recipient), 33 ether);

    // 35 + 1 > 33.6, reverts
    _expectRejectedRevert(
      address(policy),
      "mint would exceed available reserves",
      MockTokenUpgradeable.mint.selector,
      deployer,
      abi.encode(recipient, 1 ether)
    );
    token.mint(recipient, 1 ether);
  }

  function test_mint_marginModePositiveAbsolute_succeeds() public {
    vm.startPrank(deployer, deployer);

    // set margin (mintable amount = 42 ether - 2 ether = 40 ether)
    policy.setReserveMargin(SecureMintPolicy.ReserveMarginMode.PositiveAbsolute, 2 ether); // 2 ether

    // 0 + 30 <= 40, succeeds
    token.mint(recipient, 30 ether);
    assertEq(token.balanceOf(recipient), 30 ether);

    // 30 + 10 <= 40, succeeds
    token.mint(recipient, 10 ether);
    assertEq(token.balanceOf(recipient), 40 ether);
  }

  function test_mint_marginModePositiveAbsolute_reverts() public {
    vm.startPrank(deployer, deployer);

    // set margin (mintable amount = 42 ether - 2 ether = 40 ether)
    policy.setReserveMargin(SecureMintPolicy.ReserveMarginMode.PositiveAbsolute, 2 ether); // 2 ether

    // 0 + 30 <= 40, succeeds
    token.mint(recipient, 30 ether);
    assertEq(token.balanceOf(recipient), 30 ether);

    // 30 + 12 > 40, reverts
    _expectRejectedRevert(
      address(policy),
      "mint would exceed available reserves",
      MockTokenUpgradeable.mint.selector,
      deployer,
      abi.encode(recipient, 12 ether)
    );
    token.mint(recipient, 12 ether);

    // 30 + 10 <= 40, succeeds
    token.mint(recipient, 10 ether);
    assertEq(token.balanceOf(recipient), 40 ether);

    // 40 + 1 > 40, reverts
    _expectRejectedRevert(
      address(policy),
      "mint would exceed available reserves",
      MockTokenUpgradeable.mint.selector,
      deployer,
      abi.encode(recipient, 1 ether)
    );
    token.mint(recipient, 1 ether);
  }

  function test_mint_marginModePositiveAbsoluteExceedsReserves_reverts() public {
    vm.startPrank(deployer, deployer);

    // set margin greater than reserves (mintable amount = max(0, 42 ether - 50 ether) = 0 ether)
    // 50 ether > 42 ether reserves
    policy.setReserveMargin(SecureMintPolicy.ReserveMarginMode.PositiveAbsolute, 50 ether);

    // 0 + 0.1 > 0, reverts (any minting should be blocked)
    _expectRejectedRevert(
      address(policy),
      "mint would exceed available reserves",
      MockTokenUpgradeable.mint.selector,
      deployer,
      abi.encode(recipient, 0.1 ether)
    );
    token.mint(recipient, 0.1 ether);
  }

  function test_mint_marginModeNegativePercentage_succeeds() public {
    vm.startPrank(deployer, deployer);

    // set margin (mintable amount = 42 ether * (1 - (-20%)) = 50.4 ether)
    policy.setReserveMargin(SecureMintPolicy.ReserveMarginMode.NegativePercentage, 2000); // -20%

    // 0 + 50 <= 50.4, succeeds
    token.mint(recipient, 50 ether);
    assertEq(token.balanceOf(recipient), 50 ether);

    // 50 + 0.4 <= 50.4, succeeds
    token.mint(recipient, 0.4 ether);
    assertEq(token.balanceOf(recipient), 50.4 ether);
  }

  function test_mint_marginModeNegativePercentage100_succeeds() public {
    vm.startPrank(deployer, deployer);

    // set margin (mintable amount = 42 ether * (1 - (-100%)) = 84 ether)
    policy.setReserveMargin(SecureMintPolicy.ReserveMarginMode.NegativePercentage, 10000); // -100%

    // 0 + 50 <= 84, succeeds
    token.mint(recipient, 50 ether);
    assertEq(token.balanceOf(recipient), 50 ether);

    // 50 + 34 <= 84, succeeds
    token.mint(recipient, 34 ether);
    assertEq(token.balanceOf(recipient), 84 ether);
  }

  function test_mint_marginModeNegativePercentage_reverts() public {
    vm.startPrank(deployer, deployer);

    // set margin (mintable amount = 42 ether * (1 - (-20%)) = 50.4 ether)
    policy.setReserveMargin(SecureMintPolicy.ReserveMarginMode.NegativePercentage, 2000); // -20%

    // 0 + 50 <= 50.4, succeeds
    token.mint(recipient, 50 ether);
    assertEq(token.balanceOf(recipient), 50 ether);

    // 50 + 0.5 <= 50.4, reverts
    _expectRejectedRevert(
      address(policy),
      "mint would exceed available reserves",
      MockTokenUpgradeable.mint.selector,
      deployer,
      abi.encode(recipient, 0.5 ether)
    );
    token.mint(recipient, 0.5 ether);

    // 50 + 0.4 <= 50.4, succeeds
    token.mint(recipient, 0.4 ether);
    assertEq(token.balanceOf(recipient), 50.4 ether);
  }

  function test_mint_marginModeNegativeAbsolute_succeeds() public {
    vm.startPrank(deployer, deployer);

    // set margin (mintable amount = 42 ether + 2 ether = 44 ether)
    policy.setReserveMargin(SecureMintPolicy.ReserveMarginMode.NegativeAbsolute, 2 ether); // 2 ether

    // 0 + 30 <= 44, succeeds
    token.mint(recipient, 30 ether);
    assertEq(token.balanceOf(recipient), 30 ether);

    // 30 + 14 <= 44, succeeds
    token.mint(recipient, 14 ether);
    assertEq(token.balanceOf(recipient), 44 ether);
  }

  function test_mint_marginModeNegativeAbsolute_reverts() public {
    vm.startPrank(deployer, deployer);

    // set margin (mintable amount = 42 ether + 2 ether = 44 ether)
    policy.setReserveMargin(SecureMintPolicy.ReserveMarginMode.NegativeAbsolute, 2 ether); // 2 ether

    // 0 + 30 <= 44, succeeds
    token.mint(recipient, 30 ether);
    assertEq(token.balanceOf(recipient), 30 ether);

    // 30 + 14.1 <= 44, reverts
    _expectRejectedRevert(
      address(policy),
      "mint would exceed available reserves",
      MockTokenUpgradeable.mint.selector,
      deployer,
      abi.encode(recipient, 14.1 ether)
    );
    token.mint(recipient, 14.1 ether);

    // 30 + 14 <= 44, succeeds
    token.mint(recipient, 14 ether);
    assertEq(token.balanceOf(recipient), 44 ether);

    // 44 + 1 > 44, reverts
    _expectRejectedRevert(
      address(policy),
      "mint would exceed available reserves",
      MockTokenUpgradeable.mint.selector,
      deployer,
      abi.encode(recipient, 1 ether)
    );
    token.mint(recipient, 1 ether);
  }

  function test_mint_maxStalenessSeconds_succeeds() public {
    vm.startPrank(deployer, deployer);

    policy.setMaxStalenessSeconds(600);

    porFeed.setUpdatedAt(block.timestamp - 600);
    token.mint(recipient, 1 ether);
    assertEq(token.balanceOf(recipient), 1 ether);
  }

  function test_mint_maxStalenessSeconds_reverts() public {
    vm.startPrank(deployer, deployer);

    policy.setMaxStalenessSeconds(600);

    porFeed.setUpdatedAt(block.timestamp - 601);
    _expectRejectedRevert(
      address(policy),
      "reserve data is stale",
      MockTokenUpgradeable.mint.selector,
      deployer,
      abi.encode(recipient, 1 ether)
    );
    token.mint(recipient, 1 ether);
  }

  function test_mint_negativeReserve_reverts() public {
    vm.startPrank(deployer, deployer);

    // mocks a malfunctioned that returns a negative value
    porFeed.setPrice(-1 ether);

    // should revert because the reserve is negative
    _expectRejectedRevert(
      address(policy),
      "reserve value is negative",
      MockTokenUpgradeable.mint.selector,
      deployer,
      abi.encode(recipient, 1 ether)
    );
    token.mint(recipient, 1 ether);
  }
}
