// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC7943Fungible} from "../src/interfaces/IERC7943.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {ComplianceTokenERC7943} from "../src/ComplianceTokenERC7943.sol";
import {PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {IPolicy} from "@chainlink/policy-management/interfaces/IPolicy.sol";
import {OnlyOwnerPolicy} from "@chainlink/policy-management/policies/OnlyOwnerPolicy.sol";
import {OnlyAuthorizedSenderPolicy} from "@chainlink/policy-management/policies/OnlyAuthorizedSenderPolicy.sol";
import {VolumePolicy} from "@chainlink/policy-management/policies/VolumePolicy.sol";
import {BaseProxyTest} from "./helpers/BaseProxyTest.sol";
import {ERC7943MintBurnExtractor} from "@chainlink/policy-management/extractors/ERC7943MintBurnExtractor.sol";
import {
  ERC7943SetFrozenTokensExtractor
} from "@chainlink/policy-management/extractors/ERC7943SetFrozenTokensExtractor.sol";
import {
  ERC7943ForcedTransferExtractor
} from "@chainlink/policy-management/extractors/ERC7943ForcedTransferExtractor.sol";
import {ERC7943WhitelistExtractor} from "@chainlink/policy-management/extractors/ERC7943WhitelistExtractor.sol";
import {ERC20TransferExtractor} from "@chainlink/policy-management/extractors/ERC20TransferExtractor.sol";

contract ComplianceTokenERC7943Test is BaseProxyTest {
  PolicyEngine internal s_policyEngine;
  ComplianceTokenERC7943 internal s_token;
  address internal s_owner;
  address internal s_bridge;
  address internal s_enforcer;
  OnlyOwnerPolicy internal onlyOwnerPolicy;
  OnlyAuthorizedSenderPolicy internal minterBurnerList;
  OnlyAuthorizedSenderPolicy internal freezingList;
  OnlyAuthorizedSenderPolicy internal whitelistManagerList;
  VolumePolicy internal volumePolicy;

  function setUp() public {
    s_owner = makeAddr("owner");
    s_bridge = makeAddr("bridge");
    s_enforcer = makeAddr("enforcer");

    vm.startPrank(s_owner);

    s_policyEngine = _deployPolicyEngine(true, s_owner);

    // Setup extractors
    ERC20TransferExtractor transferExtractor = new ERC20TransferExtractor();
    s_policyEngine.setExtractor(IERC20.transfer.selector, address(transferExtractor));
    s_policyEngine.setExtractor(IERC20.transferFrom.selector, address(transferExtractor));

    ERC7943MintBurnExtractor mintBurnExtractor = new ERC7943MintBurnExtractor();
    s_policyEngine.setExtractor(ComplianceTokenERC7943.mint.selector, address(mintBurnExtractor));
    s_policyEngine.setExtractor(ComplianceTokenERC7943.burn.selector, address(mintBurnExtractor));
    s_policyEngine.setExtractor(ComplianceTokenERC7943.burnFrom.selector, address(mintBurnExtractor));

    ERC7943SetFrozenTokensExtractor setFrozenExtractor = new ERC7943SetFrozenTokensExtractor();
    s_policyEngine.setExtractor(IERC7943Fungible.setFrozenTokens.selector, address(setFrozenExtractor));

    ERC7943ForcedTransferExtractor forcedTransferExtractor = new ERC7943ForcedTransferExtractor();
    s_policyEngine.setExtractor(IERC7943Fungible.forcedTransfer.selector, address(forcedTransferExtractor));

    ERC7943WhitelistExtractor whitelistExtractor = new ERC7943WhitelistExtractor();
    s_policyEngine.setExtractor(ComplianceTokenERC7943.changeWhitelist.selector, address(whitelistExtractor));

    // Deploy policies
    OnlyOwnerPolicy onlyOwnerPolicyImpl = new OnlyOwnerPolicy();
    onlyOwnerPolicy =
      OnlyOwnerPolicy(_deployPolicy(address(onlyOwnerPolicyImpl), address(s_policyEngine), s_owner, new bytes(0)));

    OnlyAuthorizedSenderPolicy minterBurnerListImpl = new OnlyAuthorizedSenderPolicy();
    minterBurnerList = OnlyAuthorizedSenderPolicy(
      _deployPolicy(address(minterBurnerListImpl), address(s_policyEngine), s_owner, new bytes(0))
    );
    minterBurnerList.authorizeSender(s_owner);
    minterBurnerList.authorizeSender(s_bridge);

    OnlyAuthorizedSenderPolicy freezingListImpl = new OnlyAuthorizedSenderPolicy();
    freezingList = OnlyAuthorizedSenderPolicy(
      _deployPolicy(address(freezingListImpl), address(s_policyEngine), s_owner, new bytes(0))
    );
    freezingList.authorizeSender(s_owner);
    freezingList.authorizeSender(s_enforcer);

    OnlyAuthorizedSenderPolicy whitelistManagerListImpl = new OnlyAuthorizedSenderPolicy();
    whitelistManagerList = OnlyAuthorizedSenderPolicy(
      _deployPolicy(address(whitelistManagerListImpl), address(s_policyEngine), s_owner, new bytes(0))
    );
    whitelistManagerList.authorizeSender(s_owner);

    VolumePolicy volumePolicyImpl = new VolumePolicy();
    volumePolicy =
      VolumePolicy(_deployPolicy(address(volumePolicyImpl), address(s_policyEngine), s_owner, abi.encode(100, 200)));

    // Deploy token
    s_token = _deployComplianceTokenERC7943("Test Token", "TST", 18, address(s_policyEngine));

    bytes32[] memory volumeParams = new bytes32[](1);
    volumeParams[0] = mintBurnExtractor.PARAM_AMOUNT();

    // Setup policies for token methods
    // Admin methods - onlyOwner
    s_policyEngine.addPolicy(
      address(s_token), IERC7943Fungible.forcedTransfer.selector, address(onlyOwnerPolicy), new bytes32[](0)
    );

    // Mint - onlyAuthorized + volume
    s_policyEngine.addPolicy(
      address(s_token), ComplianceTokenERC7943.mint.selector, address(minterBurnerList), new bytes32[](0)
    );
    s_policyEngine.addPolicy(
      address(s_token), ComplianceTokenERC7943.mint.selector, address(volumePolicy), volumeParams
    );

    // Burn/burnFrom - onlyAuthorized
    s_policyEngine.addPolicy(
      address(s_token), ComplianceTokenERC7943.burn.selector, address(minterBurnerList), new bytes32[](0)
    );
    s_policyEngine.addPolicy(
      address(s_token), ComplianceTokenERC7943.burnFrom.selector, address(minterBurnerList), new bytes32[](0)
    );

    // Freezing methods - onlyAuthorized
    s_policyEngine.addPolicy(
      address(s_token), IERC7943Fungible.setFrozenTokens.selector, address(freezingList), new bytes32[](0)
    );

    // Whitelist methods - onlyAuthorized
    s_policyEngine.addPolicy(
      address(s_token), ComplianceTokenERC7943.changeWhitelist.selector, address(whitelistManagerList), new bytes32[](0)
    );

    // Transfer methods - volume
    s_policyEngine.addPolicy(address(s_token), IERC20.transfer.selector, address(volumePolicy), volumeParams);
    s_policyEngine.addPolicy(address(s_token), IERC20.transferFrom.selector, address(volumePolicy), volumeParams);
  }

  // ** Metadata Tests **

  function test_token_metadata_success() public view {
    assertEq(s_token.name(), "Test Token");
    assertEq(s_token.symbol(), "TST");
    assertEq(s_token.decimals(), 18);
  }

  // ** Whitelist Tests **

  function test_changeWhitelist_success() public {
    address alice = makeAddr("alice");

    assertEq(s_token.canSend(alice), false);
    assertEq(s_token.canReceive(alice), false);

    s_token.changeWhitelist(alice, true, true);

    assertEq(s_token.canSend(alice), true);
    assertEq(s_token.canReceive(alice), true);

    s_token.changeWhitelist(alice, false, false);

    assertEq(s_token.canSend(alice), false);
    assertEq(s_token.canReceive(alice), false);
  }

  function test_changeWhitelist_notAuthorized_revert() public {
    address alice = makeAddr("alice");

    vm.stopPrank();
    vm.startPrank(alice);

    _expectRejectedRevert(
      address(whitelistManagerList),
      "sender is not authorized",
      ComplianceTokenERC7943.changeWhitelist.selector,
      alice,
      abi.encode(alice, true, true)
    );
    s_token.changeWhitelist(alice, true, true);
  }

  // ** Mint Tests **

  function test_mint_success() public {
    address alice = makeAddr("alice");

    s_token.changeWhitelist(alice, true, true);
    s_token.mint(alice, 120);

    assertEq(s_token.balanceOf(alice), 120);
    assertEq(s_token.totalSupply(), 120);
  }

  function test_mint_bridge_success() public {
    address alice = makeAddr("alice");

    s_token.changeWhitelist(alice, true, true);

    vm.stopPrank();
    vm.startPrank(s_bridge);
    s_token.mint(alice, 120);

    assertEq(s_token.balanceOf(alice), 120);
    assertEq(s_token.totalSupply(), 120);
  }

  function test_mint_notWhitelisted_revert() public {
    address alice = makeAddr("alice");

    vm.expectRevert(abi.encodeWithSelector(IERC7943Fungible.ERC7943CannotReceive.selector, alice));
    s_token.mint(alice, 120);
  }

  function test_mint_over_failure() public {
    address alice = makeAddr("alice");

    s_token.changeWhitelist(alice, true, true);

    _expectRejectedRevert(
      address(volumePolicy),
      "amount outside allowed volume limits",
      ComplianceTokenERC7943.mint.selector,
      s_owner,
      abi.encode(alice, uint256(220))
    );
    s_token.mint(alice, 220);
  }

  function test_mint_under_failure() public {
    address alice = makeAddr("alice");

    s_token.changeWhitelist(alice, true, true);

    _expectRejectedRevert(
      address(volumePolicy),
      "amount outside allowed volume limits",
      ComplianceTokenERC7943.mint.selector,
      s_owner,
      abi.encode(alice, uint256(50))
    );
    s_token.mint(alice, 50);
  }

  function test_mint_notAuthorized_revert() public {
    address alice = makeAddr("alice");

    s_token.changeWhitelist(alice, true, true);

    vm.stopPrank();
    vm.startPrank(alice);

    _expectRejectedRevert(
      address(minterBurnerList),
      "sender is not authorized",
      ComplianceTokenERC7943.mint.selector,
      alice,
      abi.encode(alice, uint256(120))
    );
    s_token.mint(alice, 120);
  }

  // ** Burn Tests **

  function test_burn_success() public {
    address alice = makeAddr("alice");

    s_token.changeWhitelist(alice, true, true);
    s_token.changeWhitelist(s_bridge, true, true);
    s_token.mint(s_bridge, 120);

    vm.stopPrank();
    vm.startPrank(s_bridge);

    s_token.burn(50);

    assertEq(s_token.balanceOf(s_bridge), 70);
    assertEq(s_token.totalSupply(), 70);
  }

  function test_burn_overBalance_revert() public {
    s_token.changeWhitelist(s_bridge, true, true);
    s_token.mint(s_bridge, 120);

    vm.stopPrank();
    vm.startPrank(s_bridge);

    vm.expectRevert(
      abi.encodeWithSelector(IERC7943Fungible.ERC7943InsufficientUnfrozenBalance.selector, s_bridge, 121, 120)
    );
    s_token.burn(121);
  }

  function test_burn_notAuthorized_failure() public {
    address alice = makeAddr("alice");

    s_token.changeWhitelist(alice, true, true);
    s_token.mint(alice, 120);

    vm.stopPrank();
    vm.startPrank(alice);

    _expectRejectedRevert(
      address(minterBurnerList),
      "sender is not authorized",
      ComplianceTokenERC7943.burn.selector,
      alice,
      abi.encode(uint256(50))
    );
    s_token.burn(50);
  }

  function test_burnFrom_success() public {
    address alice = makeAddr("alice");

    s_token.changeWhitelist(alice, true, true);
    s_token.mint(alice, 120);

    s_token.burnFrom(alice, 70);

    assertEq(s_token.balanceOf(alice), 50);
    assertEq(s_token.totalSupply(), 50);
  }

  function test_burnFrom_bridge_success() public {
    address alice = makeAddr("alice");

    s_token.changeWhitelist(alice, true, true);
    s_token.mint(alice, 120);

    vm.stopPrank();
    vm.startPrank(s_bridge);

    s_token.burnFrom(alice, 70);

    assertEq(s_token.balanceOf(alice), 50);
    assertEq(s_token.totalSupply(), 50);
  }

  function test_burnFrom_notAuthorized_failure() public {
    address alice = makeAddr("alice");

    s_token.changeWhitelist(alice, true, true);
    s_token.mint(alice, 120);

    vm.stopPrank();
    vm.startPrank(alice);

    _expectRejectedRevert(
      address(minterBurnerList),
      "sender is not authorized",
      ComplianceTokenERC7943.burnFrom.selector,
      alice,
      abi.encode(alice, uint256(70))
    );
    s_token.burnFrom(alice, 70);
  }

  // ** Transfer Tests **

  function test_transfer_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.changeWhitelist(alice, true, true);
    s_token.changeWhitelist(bob, true, true);
    s_token.mint(alice, 170);

    vm.stopPrank();
    vm.startPrank(alice);

    s_token.transfer(bob, 110);

    assertEq(s_token.balanceOf(alice), 60);
    assertEq(s_token.balanceOf(bob), 110);
  }

  function test_transfer_notWhitelistedSender_revert() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.changeWhitelist(alice, true, true);
    s_token.changeWhitelist(bob, true, true);
    s_token.mint(alice, 170);

    // Remove alice from whitelist
    s_token.changeWhitelist(alice, false, false);

    vm.stopPrank();
    vm.startPrank(alice);

    vm.expectRevert(abi.encodeWithSelector(IERC7943Fungible.ERC7943CannotSend.selector, alice));
    s_token.transfer(bob, 110);
  }

  function test_transfer_notWhitelistedRecipient_revert() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.changeWhitelist(alice, true, true);
    s_token.mint(alice, 170);

    vm.stopPrank();
    vm.startPrank(alice);

    vm.expectRevert(abi.encodeWithSelector(IERC7943Fungible.ERC7943CannotReceive.selector, bob));
    s_token.transfer(bob, 110);
  }

  function test_transfer_over_failure() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.changeWhitelist(alice, true, true);
    s_token.changeWhitelist(bob, true, true);
    s_token.mint(alice, 120);
    s_token.mint(alice, 120);

    vm.stopPrank();
    vm.startPrank(alice);

    _expectRejectedRevert(
      address(volumePolicy),
      "amount outside allowed volume limits",
      IERC20.transfer.selector,
      alice,
      abi.encode(bob, uint256(210))
    );
    s_token.transfer(bob, 210);
  }

  function test_transfer_under_failure() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.changeWhitelist(alice, true, true);
    s_token.changeWhitelist(bob, true, true);
    s_token.mint(alice, 120);

    vm.stopPrank();
    vm.startPrank(alice);

    _expectRejectedRevert(
      address(volumePolicy),
      "amount outside allowed volume limits",
      IERC20.transfer.selector,
      alice,
      abi.encode(bob, uint256(50))
    );
    s_token.transfer(bob, 50);
  }

  // ** TransferFrom Tests **

  function test_transferFrom_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address charlie = makeAddr("charlie");

    s_token.changeWhitelist(alice, true, true);
    s_token.changeWhitelist(bob, true, true);
    s_token.mint(alice, 170);

    vm.stopPrank();
    vm.startPrank(alice);

    s_token.approve(charlie, 110);

    vm.stopPrank();
    vm.startPrank(charlie);

    s_token.transferFrom(alice, bob, 110);

    assertEq(s_token.balanceOf(alice), 60);
    assertEq(s_token.balanceOf(bob), 110);
  }

  function test_transferFrom_insufficientAllowance_revert() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address charlie = makeAddr("charlie");

    s_token.changeWhitelist(alice, true, true);
    s_token.changeWhitelist(bob, true, true);
    s_token.mint(alice, 170);

    vm.stopPrank();
    vm.startPrank(alice);

    s_token.approve(charlie, 110);

    vm.stopPrank();
    vm.startPrank(charlie);

    vm.expectRevert("ERC20: transfer amount exceeds allowance");
    s_token.transferFrom(alice, bob, 111);
  }

  // ** Frozen Token Tests **

  function test_setFrozenTokens_success() public {
    address alice = makeAddr("alice");

    s_token.changeWhitelist(alice, true, true);
    s_token.mint(alice, 120);

    s_token.setFrozenTokens(alice, 50);

    assertEq(s_token.getFrozenTokens(alice), 50);
  }

  function test_setFrozenTokens_notAuthorized_revert() public {
    address alice = makeAddr("alice");

    s_token.changeWhitelist(alice, true, true);
    s_token.mint(alice, 120);

    vm.stopPrank();
    vm.startPrank(alice);

    _expectRejectedRevert(
      address(freezingList),
      "sender is not authorized",
      IERC7943Fungible.setFrozenTokens.selector,
      alice,
      abi.encode(alice, uint256(50))
    );
    s_token.setFrozenTokens(alice, 50);
  }

  function test_transfer_frozenBalance_revert() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.changeWhitelist(alice, true, true);
    s_token.changeWhitelist(bob, true, true);
    s_token.mint(alice, 120);

    s_token.setFrozenTokens(alice, 50);

    vm.stopPrank();
    vm.startPrank(alice);

    // balance 120, frozen 50 => unfrozen 70
    vm.expectRevert(
      abi.encodeWithSelector(IERC7943Fungible.ERC7943InsufficientUnfrozenBalance.selector, alice, 110, 70)
    );
    s_token.transfer(bob, 110);
  }

  function test_transfer_partialFrozen_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.changeWhitelist(alice, true, true);
    s_token.changeWhitelist(bob, true, true);
    s_token.mint(alice, 170);

    s_token.setFrozenTokens(alice, 50);

    vm.stopPrank();
    vm.startPrank(alice);

    // Can transfer up to 120 (170 - 50 frozen)
    s_token.transfer(bob, 110);

    assertEq(s_token.balanceOf(alice), 60);
    assertEq(s_token.balanceOf(bob), 110);
  }

  function test_setFrozenTokens_enforcer_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.changeWhitelist(alice, true, true);
    s_token.changeWhitelist(bob, true, true);
    s_token.mint(alice, 120);

    vm.stopPrank();
    vm.startPrank(s_enforcer);

    s_token.setFrozenTokens(alice, 100);
    assertEq(s_token.getFrozenTokens(alice), 100);

    vm.stopPrank();
    vm.startPrank(alice);

    // balance 120, frozen 100 => unfrozen 20
    vm.expectRevert(
      abi.encodeWithSelector(IERC7943Fungible.ERC7943InsufficientUnfrozenBalance.selector, alice, 110, 20)
    );
    s_token.transfer(bob, 110);

    vm.stopPrank();
    vm.startPrank(s_enforcer);

    // Unfreeze by setting to lower amount
    s_token.setFrozenTokens(alice, 0);

    vm.stopPrank();
    vm.startPrank(alice);

    s_token.transfer(bob, 110);
    assertEq(s_token.balanceOf(alice), 10);
    assertEq(s_token.balanceOf(bob), 110);
  }

  function test_transferFrom_frozenBalance_revert() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address charlie = makeAddr("charlie");

    s_token.changeWhitelist(alice, true, true);
    s_token.changeWhitelist(bob, true, true);
    s_token.mint(alice, 150);

    s_token.setFrozenTokens(alice, 60);

    vm.stopPrank();
    vm.startPrank(alice);

    s_token.approve(charlie, 110);

    vm.stopPrank();
    vm.startPrank(charlie);

    // balance 150, frozen 60 => unfrozen 90
    vm.expectRevert(
      abi.encodeWithSelector(IERC7943Fungible.ERC7943InsufficientUnfrozenBalance.selector, alice, 110, 90)
    );
    s_token.transferFrom(alice, bob, 110);
  }

  // ** canTransfer Tests **

  function test_canTransfer_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.changeWhitelist(alice, true, true);
    s_token.changeWhitelist(bob, true, true);
    s_token.mint(alice, 120);

    assertEq(s_token.canTransfer(alice, bob, 100), true);
    assertEq(s_token.canTransfer(alice, bob, 120), true);
    assertEq(s_token.canTransfer(alice, bob, 121), false); // Exceeds balance
  }

  function test_canTransfer_frozen_failure() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.changeWhitelist(alice, true, true);
    s_token.changeWhitelist(bob, true, true);
    s_token.mint(alice, 120);

    s_token.setFrozenTokens(alice, 50);

    assertEq(s_token.canTransfer(alice, bob, 70), true);
    assertEq(s_token.canTransfer(alice, bob, 71), false); // Exceeds unfrozen balance
  }

  function test_canTransfer_notWhitelisted_failure() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.changeWhitelist(alice, true, true);
    s_token.mint(alice, 120);

    // Bob is not whitelisted
    assertEq(s_token.canTransfer(alice, bob, 100), false);
  }

  // ** Forced Transfer Tests **

  function test_forcedTransfer_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.changeWhitelist(alice, true, true);
    s_token.changeWhitelist(bob, true, true);
    s_token.mint(alice, 170);

    s_token.forcedTransfer(alice, bob, 60);

    assertEq(s_token.balanceOf(alice), 110);
    assertEq(s_token.balanceOf(bob), 60);
  }

  function test_forcedTransfer_frozenBalance_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.changeWhitelist(alice, true, true);
    s_token.changeWhitelist(bob, true, true);
    s_token.mint(alice, 170);

    s_token.setFrozenTokens(alice, 100);

    // Force transfer more than unfrozen balance
    s_token.forcedTransfer(alice, bob, 140);

    assertEq(s_token.balanceOf(alice), 30);
    assertEq(s_token.balanceOf(bob), 140);
    // Frozen tokens should have been reduced
    assertEq(s_token.getFrozenTokens(alice), 30);
  }

  function test_forcedTransfer_notOwner_revert() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.changeWhitelist(alice, true, true);
    s_token.changeWhitelist(bob, true, true);
    s_token.mint(alice, 150);

    vm.stopPrank();
    vm.startPrank(bob);

    _expectRejectedRevert(
      address(onlyOwnerPolicy),
      "caller is not the policy owner",
      IERC7943Fungible.forcedTransfer.selector,
      bob,
      abi.encode(alice, bob, uint256(60))
    );
    s_token.forcedTransfer(alice, bob, 60);
  }

  function test_forcedTransfer_notWhitelistedRecipient_revert() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.changeWhitelist(alice, true, true);
    // Bob is NOT whitelisted
    s_token.mint(alice, 150);

    vm.expectRevert(abi.encodeWithSelector(IERC7943Fungible.ERC7943CannotReceive.selector, bob));
    s_token.forcedTransfer(alice, bob, 60);
  }

  // ** ERC-165 Interface Support Tests **

  function test_supportsInterface() public view {
    // IERC7943Fungible interface ID mandated by ERC-7943: 0x3edbb4c4
    assertEq(type(IERC7943Fungible).interfaceId, bytes4(0x3edbb4c4));
    assertTrue(s_token.supportsInterface(type(IERC7943Fungible).interfaceId));
    assertTrue(s_token.supportsInterface(0x3edbb4c4));
    // IERC20 interface ID
    assertTrue(s_token.supportsInterface(type(IERC20).interfaceId));
    // IERC165 interface ID
    assertTrue(s_token.supportsInterface(0x01ffc9a7));
  }

  // ** Directional Eligibility / Burn Frozen Tests **

  function test_burn_frozenBalance_revert() public {
    s_token.changeWhitelist(s_bridge, true, true);
    s_token.mint(s_bridge, 120);
    s_token.setFrozenTokens(s_bridge, 100);

    vm.stopPrank();
    vm.startPrank(s_bridge);

    // balance 120, frozen 100 => unfrozen 20; burning 50 must revert
    vm.expectRevert(
      abi.encodeWithSelector(IERC7943Fungible.ERC7943InsufficientUnfrozenBalance.selector, s_bridge, 50, 20)
    );
    s_token.burn(50);
  }

  function test_canSendCanReceive_independent() public {
    address alice = makeAddr("alice");

    // Allowed to send only.
    s_token.changeWhitelist(alice, true, false);
    assertEq(s_token.canSend(alice), true);
    assertEq(s_token.canReceive(alice), false);

    // Allowed to receive only.
    s_token.changeWhitelist(alice, false, true);
    assertEq(s_token.canSend(alice), false);
    assertEq(s_token.canReceive(alice), true);
  }

  function test_canTransfer_oneWayRestriction_failure() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.changeWhitelist(alice, true, true);
    s_token.changeWhitelist(bob, true, true);
    s_token.mint(alice, 120);

    assertEq(s_token.canTransfer(alice, bob, 100), true);

    // Block bob from receiving while keeping his send eligibility.
    s_token.changeWhitelist(bob, true, false);
    assertEq(s_token.canSend(bob), true);
    assertEq(s_token.canReceive(bob), false);

    // alice -> bob now fails (bob cannot receive)...
    assertEq(s_token.canTransfer(alice, bob, 100), false);
    vm.stopPrank();
    vm.startPrank(alice);
    vm.expectRevert(abi.encodeWithSelector(IERC7943Fungible.ERC7943CannotReceive.selector, bob));
    s_token.transfer(bob, 100);
  }

  function test_transfer_oneWaySenderBlocked_revert() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.changeWhitelist(alice, true, true);
    s_token.changeWhitelist(bob, true, true);
    s_token.mint(alice, 120);

    // Block alice from sending while keeping her receive eligibility.
    s_token.changeWhitelist(alice, false, true);
    assertEq(s_token.canSend(alice), false);
    assertEq(s_token.canReceive(alice), true);

    vm.stopPrank();
    vm.startPrank(alice);
    vm.expectRevert(abi.encodeWithSelector(IERC7943Fungible.ERC7943CannotSend.selector, alice));
    s_token.transfer(bob, 100);
  }
}
