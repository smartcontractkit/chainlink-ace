// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IToken} from "../../../vendor/erc-3643/token/IToken.sol";
import {IPolicyEngine} from "../../../policy-management/src/interfaces/IPolicyEngine.sol";
import {ComplianceTokenERC3643} from "../src/ComplianceTokenERC3643.sol";
import {PolicyEngine} from "../../../policy-management/src/core/PolicyEngine.sol";
import {IPolicy} from "../../../policy-management/src/interfaces/IPolicy.sol";
import {OnlySubjectOwnerPolicy} from "../../../policy-management/src/policies/OnlySubjectOwnerPolicy.sol";
import {ExpectedContextPolicy} from "./helpers/ExpectedContextPolicy.sol";
import {BaseProxyTest} from "./helpers/BaseProxyTest.sol";
import {OnlyAuthorizedSenderPolicy} from "../../../policy-management/src/policies/OnlyAuthorizedSenderPolicy.sol";
import {VolumePolicy} from "../../../policy-management/src/policies/VolumePolicy.sol";
import {VolumeRatePolicy} from "../../../policy-management/src/policies/VolumeRatePolicy.sol";
import {ERC3643MintBurnExtractor} from "../../../policy-management/src/extractors/ERC3643MintBurnExtractor.sol";
import {
  ERC3643FreezeUnfreezeExtractor
} from "../../../policy-management/src/extractors/ERC3643FreezeUnfreezeExtractor.sol";
import {
  ERC3643ForcedTransferExtractor
} from "../../../policy-management/src/extractors/ERC3643ForcedTransferExtractor.sol";
import {ERC20TransferExtractor} from "../../../policy-management/src/extractors/ERC20TransferExtractor.sol";
import {
  ERC3643SetAddressFrozenExtractor
} from "../../../policy-management/src/extractors/ERC3643SetAddressFrozenExtractor.sol";

contract ComplianceTokenERC3643Test is BaseProxyTest {
  PolicyEngine internal s_policyEngine;
  ComplianceTokenERC3643 internal s_token;
  /// @dev Same source as ComplianceTokenERC3643.TOKEN_VERSION (see ComplianceTokenERC3643VersionRef below).
  string internal s_expectedTokenVersion;
  address internal s_owner;
  address internal s_token_owner;
  address internal s_bridge;
  address internal s_enforcer;
  OnlySubjectOwnerPolicy internal onlySubjectOwnerPolicy;
  OnlyAuthorizedSenderPolicy internal minterBurnerList;
  OnlyAuthorizedSenderPolicy internal freezingList;
  VolumePolicy internal volumePolicy;

  function setUp() public {
    s_expectedTokenVersion = new ComplianceTokenERC3643VersionRef().tokenVersionExpected();

    s_owner = makeAddr("owner");
    s_token_owner = makeAddr("token_owner");
    s_bridge = makeAddr("bridge");
    s_enforcer = makeAddr("enforcer");

    vm.startPrank(s_owner);

    s_policyEngine = _deployPolicyEngine(true, s_owner);

    ERC20TransferExtractor transferExtractor = new ERC20TransferExtractor();
    s_policyEngine.setExtractor(IERC20.transfer.selector, address(transferExtractor));
    s_policyEngine.setExtractor(IERC20.transferFrom.selector, address(transferExtractor));
    ERC3643MintBurnExtractor mintBurnExtractor = new ERC3643MintBurnExtractor();
    s_policyEngine.setExtractor(IToken.mint.selector, address(mintBurnExtractor));
    s_policyEngine.setExtractor(IToken.burn.selector, address(mintBurnExtractor));
    ERC3643FreezeUnfreezeExtractor freezeUnfreezeExtractor = new ERC3643FreezeUnfreezeExtractor();
    s_policyEngine.setExtractor(IToken.freezePartialTokens.selector, address(freezeUnfreezeExtractor));
    s_policyEngine.setExtractor(IToken.unfreezePartialTokens.selector, address(freezeUnfreezeExtractor));
    s_policyEngine.setExtractor(IToken.forcedTransfer.selector, address(new ERC3643ForcedTransferExtractor()));
    s_policyEngine.setExtractor(IToken.setAddressFrozen.selector, address(new ERC3643SetAddressFrozenExtractor()));

    // to protect admin methods
    OnlySubjectOwnerPolicy onlySubjectOwnerPolicyImpl = new OnlySubjectOwnerPolicy();
    onlySubjectOwnerPolicy = OnlySubjectOwnerPolicy(
      _deployPolicy(address(onlySubjectOwnerPolicyImpl), address(s_policyEngine), address(s_policyEngine), new bytes(0))
    );
    // to protect mint/burn with admin list
    OnlyAuthorizedSenderPolicy minterBurnerListImpl = new OnlyAuthorizedSenderPolicy();
    minterBurnerList = OnlyAuthorizedSenderPolicy(
      _deployPolicy(address(minterBurnerListImpl), address(s_policyEngine), address(s_policyEngine), new bytes(0))
    );
    s_policyEngine.setPolicyConfiguration(
      address(minterBurnerList), 0, OnlyAuthorizedSenderPolicy.authorizeSender.selector, abi.encode(s_owner)
    );
    s_policyEngine.setPolicyConfiguration(
      address(minterBurnerList), 1, OnlyAuthorizedSenderPolicy.authorizeSender.selector, abi.encode(s_bridge)
    );
    // to protect freezing features with admin list
    OnlyAuthorizedSenderPolicy freezingListImpl = new OnlyAuthorizedSenderPolicy();
    freezingList = OnlyAuthorizedSenderPolicy(
      _deployPolicy(address(freezingListImpl), address(s_policyEngine), address(s_policyEngine), new bytes(0))
    );
    s_policyEngine.setPolicyConfiguration(
      address(freezingList), 0, OnlyAuthorizedSenderPolicy.authorizeSender.selector, abi.encode(s_owner)
    );
    s_policyEngine.setPolicyConfiguration(
      address(freezingList), 1, OnlyAuthorizedSenderPolicy.authorizeSender.selector, abi.encode(s_enforcer)
    );
    // to enforce transaction limits
    VolumePolicy volumePolicyImpl = new VolumePolicy();
    volumePolicy = VolumePolicy(
      _deployPolicy(address(volumePolicyImpl), address(s_policyEngine), address(s_policyEngine), abi.encode(100, 200))
    );

    // make token owner distinct from ACE contracts owner
    s_token = _deployComplianceTokenERC3643("Test Token", "TST", 18, address(s_policyEngine));
    s_token.transferOwnership(s_token_owner);

    bytes32[] memory volumeParams = new bytes32[](1);
    volumeParams[0] = mintBurnExtractor.PARAM_AMOUNT();

    // admin methods - onlyOwner
    s_policyEngine.addPolicy(
      address(s_token), IToken.setName.selector, address(onlySubjectOwnerPolicy), new bytes32[](0)
    );
    s_policyEngine.addPolicy(
      address(s_token), IToken.setSymbol.selector, address(onlySubjectOwnerPolicy), new bytes32[](0)
    );
    s_policyEngine.addPolicy(address(s_token), IToken.pause.selector, address(onlySubjectOwnerPolicy), new bytes32[](0));
    s_policyEngine.addPolicy(
      address(s_token), IToken.unpause.selector, address(onlySubjectOwnerPolicy), new bytes32[](0)
    );
    s_policyEngine.addPolicy(
      address(s_token), IToken.forcedTransfer.selector, address(onlySubjectOwnerPolicy), new bytes32[](0)
    );
    // mint - onlyAuthorized - volume
    s_policyEngine.addPolicy(address(s_token), IToken.mint.selector, address(minterBurnerList), new bytes32[](0));
    s_policyEngine.addPolicy(address(s_token), IToken.mint.selector, address(volumePolicy), volumeParams);
    // burn - onlyAuthorized
    s_policyEngine.addPolicy(address(s_token), IToken.burn.selector, address(minterBurnerList), new bytes32[](0));
    // freezing methods - onlyAuthorized
    s_policyEngine.addPolicy(
      address(s_token), IToken.freezePartialTokens.selector, address(freezingList), new bytes32[](0)
    );
    s_policyEngine.addPolicy(
      address(s_token), IToken.unfreezePartialTokens.selector, address(freezingList), new bytes32[](0)
    );
    s_policyEngine.addPolicy(
      address(s_token), IToken.setAddressFrozen.selector, address(freezingList), new bytes32[](0)
    );
    // transfer methods - volume
    s_policyEngine.addPolicy(address(s_token), IERC20.transfer.selector, address(volumePolicy), volumeParams);
    s_policyEngine.addPolicy(address(s_token), IERC20.transferFrom.selector, address(volumePolicy), volumeParams);
  }

  function test_token_metadata_success() public {
    vm.startPrank(s_token_owner);
    assertEq(s_token.name(), "Test Token");
    assertEq(s_token.symbol(), "TST");
    assertEq(s_token.decimals(), 18);
    assertEq(s_token.onchainID(), address(0));
    assertEq(s_token.version(), s_expectedTokenVersion);

    s_token.setName("New Name");
    s_token.setSymbol("NME");

    assertEq(s_token.name(), "New Name");
    assertEq(s_token.symbol(), "NME");
  }

  function test_token_name_notOwner_failure() public {
    vm.startPrank(s_bridge);

    _expectRejectedRevert(
      address(onlySubjectOwnerPolicy),
      "caller is not the subject owner",
      IToken.setName.selector,
      s_bridge,
      abi.encode("New Name")
    );
    s_token.setName("New Name");
  }

  function test_token_symbol_notOwner_failure() public {
    vm.startPrank(s_bridge);

    _expectRejectedRevert(
      address(onlySubjectOwnerPolicy),
      "caller is not the subject owner",
      IToken.setSymbol.selector,
      s_bridge,
      abi.encode("NME")
    );
    s_token.setSymbol("NME");
  }

  function test_mint_success() public {
    address alice = makeAddr("alice");

    s_token.mint(alice, 120);

    assertEq(s_token.balanceOf(alice), 120);
    assertEq(s_token.totalSupply(), 120);
  }

  function test_mint_WithContext_success() public {
    address alice = makeAddr("alice");

    ExpectedContextPolicy expectedContextPolicyImpl = new ExpectedContextPolicy();
    ExpectedContextPolicy expectedContextPolicy = ExpectedContextPolicy(
      _deployPolicy(
        address(expectedContextPolicyImpl), address(s_policyEngine), address(this), abi.encode("mint context")
      )
    );

    s_policyEngine.addPolicy(address(s_token), IToken.mint.selector, address(expectedContextPolicy), new bytes32[](0));

    s_token.setContext("mint context");
    s_token.mint(alice, 110);

    assertEq(s_token.balanceOf(alice), 110);
    assertEq(s_token.totalSupply(), 110);

    // second mint fails because context was cleared after the last mint
    _expectRejectedRevert(
      address(expectedContextPolicy),
      "context does not match expected value",
      IToken.mint.selector,
      s_owner,
      abi.encode(alice, 110)
    );
    s_token.mint(alice, 110);
  }

  function test_mint_bridge_success() public {
    address alice = makeAddr("alice");

    vm.startPrank(s_bridge);
    s_token.mint(alice, 120);

    assertEq(s_token.balanceOf(alice), 120);
    assertEq(s_token.totalSupply(), 120);
  }

  function test_mint_over_failure() public {
    address alice = makeAddr("alice");

    _expectRejectedRevert(
      address(volumePolicy),
      "amount outside allowed volume limits",
      IToken.mint.selector,
      s_owner,
      abi.encode(alice, 220)
    );
    s_token.mint(alice, 220);
  }

  function test_mint_under_failure() public {
    address alice = makeAddr("alice");

    IPolicyEngine.Payload memory payload = IPolicyEngine.Payload({
      selector: IToken.mint.selector, sender: s_owner, data: abi.encode(alice, 50), context: new bytes(0)
    });
    _expectRejectedRevert(address(volumePolicy), "amount outside allowed volume limits", payload);
    s_token.mint(alice, 50);
  }

  function test_mint_notAuthorized_revert() public {
    address alice = makeAddr("alice");

    vm.startPrank(alice);

    IPolicyEngine.Payload memory payload = IPolicyEngine.Payload({
      selector: IToken.mint.selector, sender: alice, data: abi.encode(alice, 10), context: new bytes(0)
    });
    _expectRejectedRevert(address(minterBurnerList), "sender is not authorized", payload);
    s_token.mint(alice, 10);
  }

  function test_burn_success() public {
    address alice = makeAddr("alice");

    s_token.mint(alice, 120);
    assertEq(s_token.balanceOf(alice), 120);

    s_token.burn(alice, 70);

    assertEq(s_token.balanceOf(alice), 50);
    assertEq(s_token.totalSupply(), 50);
  }

  function test_burn_bridge_success() public {
    address alice = makeAddr("alice");
    s_token.mint(alice, 120);
    assertEq(s_token.balanceOf(alice), 120);

    vm.startPrank(s_bridge);

    s_token.burn(alice, 70);

    assertEq(s_token.balanceOf(alice), 50);
    assertEq(s_token.totalSupply(), 50);
  }

  function test_burn_notAuthorized_failure() public {
    address alice = makeAddr("alice");
    s_token.mint(alice, 120);
    assertEq(s_token.balanceOf(alice), 120);

    vm.startPrank(alice);

    IPolicyEngine.Payload memory payload = IPolicyEngine.Payload({
      selector: IToken.burn.selector, sender: alice, data: abi.encode(alice, 70), context: new bytes(0)
    });
    _expectRejectedRevert(address(minterBurnerList), "sender is not authorized", payload);
    s_token.burn(alice, 70);
  }

  function test_transfer_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 120);

    vm.startPrank(alice);

    s_token.transfer(bob, 110);

    assertEq(s_token.balanceOf(alice), 10);
    assertEq(s_token.balanceOf(bob), 110);
  }

  function test_transfer_over_failure() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 120);
    s_token.mint(alice, 120);
    assertEq(s_token.balanceOf(alice), 240);

    vm.startPrank(alice);

    IPolicyEngine.Payload memory payload = IPolicyEngine.Payload({
      selector: IERC20.transfer.selector, sender: alice, data: abi.encode(bob, 210), context: new bytes(0)
    });
    _expectRejectedRevert(address(volumePolicy), "amount outside allowed volume limits", payload);
    s_token.transfer(bob, 210);
  }

  function test_transfer_under_failure() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 120);

    vm.startPrank(alice);

    IPolicyEngine.Payload memory payload2 = IPolicyEngine.Payload({
      selector: IERC20.transfer.selector, sender: alice, data: abi.encode(bob, 50), context: new bytes(0)
    });
    _expectRejectedRevert(address(volumePolicy), "amount outside allowed volume limits", payload2);
    s_token.transfer(bob, 50);
  }

  function test_transfer_paused_revert() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 120);

    vm.startPrank(s_token_owner);
    s_token.pause();
    assertEq(s_token.paused(), true);

    vm.startPrank(alice);

    vm.expectRevert("Pausable: paused");
    s_token.transfer(bob, 110);
  }

  function test_transfer_pause_notOwner_revert() public {
    address alice = makeAddr("alice");
    vm.startPrank(alice);

    IPolicyEngine.Payload memory payload = IPolicyEngine.Payload({
      selector: IToken.pause.selector, sender: alice, data: new bytes(0), context: new bytes(0)
    });
    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyRunRejected.selector,
        address(onlySubjectOwnerPolicy),
        "caller is not the subject owner",
        payload
      )
    );
    s_token.pause();
  }

  function test_transfer_pausedUnpaused_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 120);

    vm.startPrank(s_token_owner);
    s_token.pause();
    assertEq(s_token.paused(), true);

    s_token.unpause();
    assertEq(s_token.paused(), false);

    vm.startPrank(alice);

    s_token.transfer(bob, 110);
    assertEq(s_token.balanceOf(alice), 10);
    assertEq(s_token.balanceOf(bob), 110);
  }

  function test_transfer_unpaused_notOwner_failure() public {
    address alice = makeAddr("alice");
    vm.startPrank(s_token_owner);
    s_token.pause();
    assertEq(s_token.paused(), true);

    vm.startPrank(alice);

    IPolicyEngine.Payload memory payload = IPolicyEngine.Payload({
      selector: IToken.unpause.selector, sender: alice, data: new bytes(0), context: new bytes(0)
    });
    _expectRejectedRevert(address(onlySubjectOwnerPolicy), "caller is not the subject owner", payload);
    s_token.unpause();
  }

  function test_transfer_frozenUnfrozen_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 120);

    s_token.setAddressFrozen(alice, true);
    assertEq(s_token.isFrozen(alice), true);

    vm.startPrank(alice);

    vm.expectRevert("wallet is frozen");
    s_token.transfer(bob, 110);

    vm.startPrank(s_owner);

    s_token.setAddressFrozen(alice, false);
    assertEq(s_token.isFrozen(alice), false);

    vm.startPrank(alice);

    s_token.transfer(bob, 110);
    assertEq(s_token.balanceOf(alice), 10);
    assertEq(s_token.balanceOf(bob), 110);
  }

  function test_frozenUnfrozen_enforcer_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 120);

    vm.startPrank(s_enforcer);
    s_token.setAddressFrozen(alice, true);
    assertEq(s_token.isFrozen(alice), true);

    vm.startPrank(alice);

    vm.expectRevert("wallet is frozen");
    s_token.transfer(bob, 110);

    vm.startPrank(s_enforcer);

    s_token.setAddressFrozen(alice, false);
    assertEq(s_token.isFrozen(alice), false);

    vm.startPrank(alice);

    s_token.transfer(bob, 110);
    assertEq(s_token.balanceOf(alice), 10);
    assertEq(s_token.balanceOf(bob), 110);
  }

  function test_frozen_notAuthorized_failure() public {
    address alice = makeAddr("alice");

    s_token.mint(alice, 120);

    vm.startPrank(alice);
    IPolicyEngine.Payload memory payload = IPolicyEngine.Payload({
      selector: IToken.setAddressFrozen.selector, sender: alice, data: abi.encode(alice, true), context: new bytes(0)
    });
    _expectRejectedRevert(address(freezingList), "sender is not authorized", payload);
    s_token.setAddressFrozen(alice, true);
  }

  function test_transferFrom_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address charlie = makeAddr("charlie");

    s_token.mint(alice, 199);

    vm.startPrank(alice);

    s_token.approve(charlie, 110);

    vm.startPrank(charlie);

    s_token.transferFrom(alice, bob, 110);

    assertEq(s_token.balanceOf(alice), 89);
    assertEq(s_token.balanceOf(bob), 110);
  }

  function test_transferFrom_increasedAllowance_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address charlie = makeAddr("charlie");

    s_token.mint(alice, 150);

    vm.startPrank(alice);

    s_token.approve(charlie, 50);
    s_token.increaseAllowance(charlie, 60);
    assertEq(s_token.allowance(alice, charlie), 110);

    vm.startPrank(charlie);

    s_token.transferFrom(alice, bob, 110);

    assertEq(s_token.balanceOf(alice), 40);
    assertEq(s_token.balanceOf(bob), 110);
  }

  function test_approve_paused_revert() public {
    address alice = makeAddr("alice");
    address charlie = makeAddr("charlie");

    s_token.mint(alice, 110);
    vm.startPrank(s_token_owner);
    s_token.pause();

    vm.startPrank(alice);

    vm.expectRevert("Pausable: paused");
    s_token.approve(charlie, 5);
  }

  function test_transferFrom_paused_revert() public {
    address alice = makeAddr("alice");
    address charlie = makeAddr("charlie");

    s_token.mint(alice, 150);

    vm.startPrank(alice);
    s_token.approve(charlie, 50);

    vm.startPrank(s_token_owner);
    s_token.pause();

    vm.startPrank(alice);
    vm.expectRevert("Pausable: paused");
    s_token.approve(charlie, 60);
  }

  function test_transferFrom_insufficientAllowance_revert() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address charlie = makeAddr("charlie");

    s_token.mint(alice, 150);

    vm.startPrank(alice);
    s_token.approve(charlie, 50);

    vm.startPrank(charlie);
    vm.expectRevert(); // panic: arithmetic underflow or overflow
    s_token.transferFrom(alice, bob, 110);
  }

  function test_transferFrom_decreaseAllowance_revert() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address charlie = makeAddr("charlie");

    s_token.mint(alice, 150);

    vm.startPrank(alice);
    s_token.approve(charlie, 110);
    s_token.decreaseAllowance(charlie, 20);

    vm.startPrank(charlie);
    vm.expectRevert(); // panic: arithmetic underflow or overflow
    s_token.transferFrom(alice, bob, 110);
  }

  function test_transferFrom_frozenBalance_revert() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address charlie = makeAddr("charlie");

    s_token.mint(alice, 150);

    s_token.freezePartialTokens(alice, 60);
    assertEq(s_token.getFrozenTokens(alice), 60);

    vm.startPrank(alice);
    s_token.approve(charlie, 50);

    vm.startPrank(charlie);
    vm.expectRevert("Insufficient Balance");
    s_token.transferFrom(alice, bob, 110);
  }

  function test_transfer_frozenBalance_revert() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 120);
    s_token.freezePartialTokens(alice, 50);

    vm.startPrank(alice);
    vm.expectRevert("Insufficient Balance");
    s_token.transfer(bob, 110);
  }

  function test_transfer_partialUnfrozen_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 120);
    s_token.freezePartialTokens(alice, 10);

    vm.startPrank(alice);
    s_token.transfer(bob, 105);

    assertEq(s_token.balanceOf(alice), 15);
    assertEq(s_token.balanceOf(bob), 105);
  }

  function test_transfer_partialUnfrozen_enforcer_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 120);
    vm.startPrank(s_enforcer);
    s_token.freezePartialTokens(alice, 10);

    vm.startPrank(alice);
    s_token.transfer(bob, 105);

    assertEq(s_token.balanceOf(alice), 15);
    assertEq(s_token.balanceOf(bob), 105);
  }

  function test_transfer_partialFreeze_notAuthorized_failure() public {
    address alice = makeAddr("alice");

    s_token.mint(alice, 120);
    vm.startPrank(alice);
    IPolicyEngine.Payload memory payload = IPolicyEngine.Payload({
      selector: IToken.freezePartialTokens.selector, sender: alice, data: abi.encode(alice, 10), context: new bytes(0)
    });
    _expectRejectedRevert(address(freezingList), "sender is not authorized", payload);
    s_token.freezePartialTokens(alice, 10);
  }

  function test_transfer_unfreezeBalance_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 120);
    s_token.freezePartialTokens(alice, 50);
    assertEq(s_token.getFrozenTokens(alice), 50);

    vm.startPrank(alice);
    vm.expectRevert("Insufficient Balance");
    s_token.transfer(bob, 110);

    vm.startPrank(s_owner);
    s_token.unfreezePartialTokens(alice, 40);
    assertEq(s_token.getFrozenTokens(alice), 10);

    vm.startPrank(alice);
    s_token.transfer(bob, 110);

    assertEq(s_token.balanceOf(alice), 10);
    assertEq(s_token.balanceOf(bob), 110);
  }

  function test_transfer_partialUnfrozen_notAuthorized_failure() public {
    address alice = makeAddr("alice");

    s_token.mint(alice, 120);
    s_token.freezePartialTokens(alice, 50);

    vm.startPrank(alice);
    IPolicyEngine.Payload memory payload = IPolicyEngine.Payload({
      selector: IToken.unfreezePartialTokens.selector, sender: alice, data: abi.encode(alice, 10), context: new bytes(0)
    });
    _expectRejectedRevert(address(freezingList), "sender is not authorized", payload);
    s_token.unfreezePartialTokens(alice, 10);
  }

  function test_forcedTransfer_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 110);
    vm.startPrank(s_token_owner);
    s_token.forcedTransfer(alice, bob, 60);

    assertEq(s_token.balanceOf(alice), 50);
    assertEq(s_token.balanceOf(bob), 60);
  }

  function test_forcedTransfer_frozenBalance_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 150);

    s_token.freezePartialTokens(alice, 90);
    vm.startPrank(s_token_owner);
    s_token.forcedTransfer(alice, bob, 90);

    assertEq(s_token.balanceOf(alice), 60);
    assertEq(s_token.balanceOf(bob), 90);
  }

  function test_forcedTransfer_notOwner_revert() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 150);

    vm.startPrank(bob);
    IPolicyEngine.Payload memory payload = IPolicyEngine.Payload({
      selector: IToken.forcedTransfer.selector, sender: bob, data: abi.encode(alice, bob, 60), context: new bytes(0)
    });
    _expectRejectedRevert(address(onlySubjectOwnerPolicy), "caller is not the subject owner", payload);
    s_token.forcedTransfer(alice, bob, 60);
  }

  function test_setOnchainID_revert() public {
    vm.expectRevert("Not implemented");
    s_token.setOnchainID(makeAddr("onchainID"));
  }

  function test_setIdentityRegistry_revert() public {
    vm.expectRevert("Not implemented");
    s_token.setIdentityRegistry(makeAddr("IdentityRegistry"));
    assertEq(address(s_token.identityRegistry()), address(0));
  }

  function test_setCompliance_revert() public {
    vm.expectRevert("Not implemented");
    s_token.setCompliance(makeAddr("ModularCompliance"));
    assertEq(address(s_token.compliance()), address(0));
  }

  function test_recoveryAddress_revert() public {
    vm.expectRevert("Not implemented");
    s_token.recoveryAddress(makeAddr("old"), makeAddr("new"), makeAddr("onchainId"));
  }

  // --- batchMint ---

  function test_batchMint_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    address[] memory toList = new address[](2);
    toList[0] = alice;
    toList[1] = bob;
    uint256[] memory amounts = new uint256[](2);
    amounts[0] = 110;
    amounts[1] = 150;

    s_token.batchMint(toList, amounts);

    assertEq(s_token.balanceOf(alice), 110);
    assertEq(s_token.balanceOf(bob), 150);
    assertEq(s_token.totalSupply(), 260);
  }

  function test_batchMint_lengthMismatch_revert() public {
    address[] memory toList = new address[](2);
    toList[0] = makeAddr("alice");
    toList[1] = makeAddr("bob");
    uint256[] memory amounts = new uint256[](1);
    amounts[0] = 110;

    vm.expectRevert(abi.encodeWithSelector(ComplianceTokenERC3643.LengthMismatch.selector));
    s_token.batchMint(toList, amounts);
  }

  function test_batchMint_notAuthorized_revert() public {
    address alice = makeAddr("alice");
    address unauthorized = makeAddr("unauthorized");

    address[] memory toList = new address[](1);
    toList[0] = alice;
    uint256[] memory amounts = new uint256[](1);
    amounts[0] = 110;

    vm.startPrank(unauthorized);
    _expectRejectedRevert(
      address(minterBurnerList),
      "sender is not authorized",
      IToken.mint.selector,
      unauthorized,
      abi.encode(alice, uint256(110))
    );
    s_token.batchMint(toList, amounts);
  }

  function test_batchMint_volumeExceeded_revert() public {
    address alice = makeAddr("alice");

    address[] memory toList = new address[](1);
    toList[0] = alice;
    uint256[] memory amounts = new uint256[](1);
    amounts[0] = 220;

    _expectRejectedRevert(
      address(volumePolicy),
      "amount outside allowed volume limits",
      IToken.mint.selector,
      s_owner,
      abi.encode(alice, uint256(220))
    );
    s_token.batchMint(toList, amounts);
  }

  // --- batchBurn ---

  function test_batchBurn_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 150);
    s_token.mint(bob, 120);

    address[] memory users = new address[](2);
    users[0] = alice;
    users[1] = bob;
    uint256[] memory amounts = new uint256[](2);
    amounts[0] = 100;
    amounts[1] = 110;

    s_token.batchBurn(users, amounts);

    assertEq(s_token.balanceOf(alice), 50);
    assertEq(s_token.balanceOf(bob), 10);
    assertEq(s_token.totalSupply(), 60);
  }

  function test_batchBurn_lengthMismatch_revert() public {
    address[] memory users = new address[](2);
    users[0] = makeAddr("alice");
    users[1] = makeAddr("bob");
    uint256[] memory amounts = new uint256[](1);
    amounts[0] = 100;

    vm.expectRevert(abi.encodeWithSelector(ComplianceTokenERC3643.LengthMismatch.selector));
    s_token.batchBurn(users, amounts);
  }

  function test_batchBurn_notAuthorized_revert() public {
    address alice = makeAddr("alice");
    address unauthorized = makeAddr("unauthorized");

    s_token.mint(alice, 150);

    address[] memory users = new address[](1);
    users[0] = alice;
    uint256[] memory amounts = new uint256[](1);
    amounts[0] = 110;

    vm.startPrank(unauthorized);
    _expectRejectedRevert(
      address(minterBurnerList),
      "sender is not authorized",
      IToken.burn.selector,
      unauthorized,
      abi.encode(alice, uint256(110))
    );
    s_token.batchBurn(users, amounts);
  }

  // --- batchTransfer ---

  function test_batchTransfer_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address carol = makeAddr("carol");

    s_token.mint(alice, 150);
    s_token.mint(alice, 150);

    vm.startPrank(alice);

    address[] memory toList = new address[](2);
    toList[0] = bob;
    toList[1] = carol;
    uint256[] memory amounts = new uint256[](2);
    amounts[0] = 110;
    amounts[1] = 130;

    s_token.batchTransfer(toList, amounts);

    assertEq(s_token.balanceOf(alice), 60);
    assertEq(s_token.balanceOf(bob), 110);
    assertEq(s_token.balanceOf(carol), 130);
  }

  function test_batchTransfer_lengthMismatch_revert() public {
    address alice = makeAddr("alice");
    s_token.mint(alice, 150);

    vm.startPrank(alice);

    address[] memory toList = new address[](2);
    toList[0] = makeAddr("bob");
    toList[1] = makeAddr("carol");
    uint256[] memory amounts = new uint256[](1);
    amounts[0] = 110;

    vm.expectRevert(abi.encodeWithSelector(ComplianceTokenERC3643.LengthMismatch.selector));
    s_token.batchTransfer(toList, amounts);
  }

  function test_batchTransfer_paused_revert() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 150);

    vm.startPrank(s_token_owner);
    s_token.pause();

    vm.startPrank(alice);

    address[] memory toList = new address[](1);
    toList[0] = bob;
    uint256[] memory amounts = new uint256[](1);
    amounts[0] = 110;

    vm.expectRevert("Pausable: paused");
    s_token.batchTransfer(toList, amounts);
  }

  function test_batchTransfer_volumeRatePolicy_success() public {
    ERC20TransferExtractor transferExtractorRef = new ERC20TransferExtractor();
    bytes32[] memory vrpParams = new bytes32[](2);
    vrpParams[0] = transferExtractorRef.PARAM_AMOUNT();
    vrpParams[1] = transferExtractorRef.PARAM_FROM();

    VolumeRatePolicy volumeRatePolicyImpl = new VolumeRatePolicy();
    VolumeRatePolicy volumeRatePolicy = VolumeRatePolicy(
      _deployPolicy(
        address(volumeRatePolicyImpl), address(s_policyEngine), address(s_policyEngine), abi.encode(1 days, 300)
      )
    );
    s_policyEngine.addPolicy(address(s_token), IERC20.transfer.selector, address(volumeRatePolicy), vrpParams);

    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address carol = makeAddr("carol");

    s_token.mint(alice, 150);
    s_token.mint(alice, 150);

    vm.startPrank(alice);

    address[] memory toList = new address[](2);
    toList[0] = bob;
    toList[1] = carol;
    uint256[] memory amounts = new uint256[](2);
    amounts[0] = 110; // cumulative from alice: 110 <= 300
    amounts[1] = 180; // cumulative from alice: 290 <= 300

    s_token.batchTransfer(toList, amounts);

    assertEq(s_token.balanceOf(alice), 10);
    assertEq(s_token.balanceOf(bob), 110);
    assertEq(s_token.balanceOf(carol), 180);
  }

  function test_batchTransfer_volumeRatePolicy_secondExceedsLimit_revert() public {
    ERC20TransferExtractor transferExtractorRef = new ERC20TransferExtractor();
    bytes32[] memory vrpParams = new bytes32[](2);
    vrpParams[0] = transferExtractorRef.PARAM_AMOUNT();
    vrpParams[1] = transferExtractorRef.PARAM_FROM();

    VolumeRatePolicy volumeRatePolicyImpl = new VolumeRatePolicy();
    VolumeRatePolicy volumeRatePolicy = VolumeRatePolicy(
      _deployPolicy(
        address(volumeRatePolicyImpl), address(s_policyEngine), address(s_policyEngine), abi.encode(1 days, 300)
      )
    );
    s_policyEngine.addPolicy(address(s_token), IERC20.transfer.selector, address(volumeRatePolicy), vrpParams);

    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address carol = makeAddr("carol");

    s_token.mint(alice, 150);
    s_token.mint(alice, 150);
    s_token.mint(alice, 150);

    vm.startPrank(alice);

    address[] memory toList = new address[](2);
    toList[0] = bob;
    toList[1] = carol;
    uint256[] memory amounts = new uint256[](2);
    amounts[0] = 150; // cumulative from alice: 150 <= 300, succeeds
    amounts[1] = 160; // cumulative from alice: 310 > 300, VolumeRatePolicy rejects

    _expectRejectedRevert(
      address(volumeRatePolicy),
      "volume rate limit exceeded for time period",
      IERC20.transfer.selector,
      alice,
      abi.encode(carol, uint256(160))
    );
    s_token.batchTransfer(toList, amounts);
  }

  // --- batchForcedTransfer ---

  function test_batchForcedTransfer_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address carol = makeAddr("carol");
    address dave = makeAddr("dave");

    s_token.mint(alice, 150);
    s_token.mint(bob, 120);

    vm.startPrank(s_token_owner);

    address[] memory fromList = new address[](2);
    fromList[0] = alice;
    fromList[1] = bob;
    address[] memory toList = new address[](2);
    toList[0] = carol;
    toList[1] = dave;
    uint256[] memory amounts = new uint256[](2);
    amounts[0] = 100;
    amounts[1] = 110;

    s_token.batchForcedTransfer(fromList, toList, amounts);

    assertEq(s_token.balanceOf(alice), 50);
    assertEq(s_token.balanceOf(bob), 10);
    assertEq(s_token.balanceOf(carol), 100);
    assertEq(s_token.balanceOf(dave), 110);
  }

  function test_batchForcedTransfer_lengthMismatch_revert() public {
    vm.startPrank(s_token_owner);

    address[] memory fromList = new address[](2);
    fromList[0] = makeAddr("alice");
    fromList[1] = makeAddr("bob");
    address[] memory toList = new address[](1);
    toList[0] = makeAddr("carol");
    uint256[] memory amounts = new uint256[](2);
    amounts[0] = 100;
    amounts[1] = 110;

    vm.expectRevert(abi.encodeWithSelector(ComplianceTokenERC3643.LengthMismatch.selector));
    s_token.batchForcedTransfer(fromList, toList, amounts);
  }

  function test_batchForcedTransfer_notOwner_revert() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address carol = makeAddr("carol");

    s_token.mint(alice, 150);

    vm.startPrank(bob);

    address[] memory fromList = new address[](1);
    fromList[0] = alice;
    address[] memory toList = new address[](1);
    toList[0] = carol;
    uint256[] memory amounts = new uint256[](1);
    amounts[0] = 110;

    _expectRejectedRevert(
      address(onlySubjectOwnerPolicy),
      "caller is not the subject owner",
      IToken.forcedTransfer.selector,
      bob,
      abi.encode(alice, carol, uint256(110))
    );
    s_token.batchForcedTransfer(fromList, toList, amounts);
  }

  function test_batchForcedTransfer_frozenBalance_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 150);
    s_token.freezePartialTokens(alice, 80);

    vm.startPrank(s_token_owner);

    address[] memory fromList = new address[](1);
    fromList[0] = alice;
    address[] memory toList = new address[](1);
    toList[0] = bob;
    uint256[] memory amounts = new uint256[](1);
    amounts[0] = 100;

    s_token.batchForcedTransfer(fromList, toList, amounts);

    assertEq(s_token.balanceOf(alice), 50);
    assertEq(s_token.balanceOf(bob), 100);
    assertEq(s_token.getFrozenTokens(alice), 50);
  }

  // --- batchSetAddressFrozen ---

  function test_batchSetAddressFrozen_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 120);
    s_token.mint(bob, 120);

    address[] memory users = new address[](2);
    users[0] = alice;
    users[1] = bob;
    bool[] memory freezeFlags = new bool[](2);
    freezeFlags[0] = true;
    freezeFlags[1] = true;

    s_token.batchSetAddressFrozen(users, freezeFlags);

    assertEq(s_token.isFrozen(alice), true);
    assertEq(s_token.isFrozen(bob), true);

    freezeFlags[0] = false;
    s_token.batchSetAddressFrozen(users, freezeFlags);

    assertEq(s_token.isFrozen(alice), false);
    assertEq(s_token.isFrozen(bob), true);
  }

  function test_batchSetAddressFrozen_lengthMismatch_revert() public {
    address[] memory users = new address[](2);
    users[0] = makeAddr("alice");
    users[1] = makeAddr("bob");
    bool[] memory freezeFlags = new bool[](1);
    freezeFlags[0] = true;

    vm.expectRevert(abi.encodeWithSelector(ComplianceTokenERC3643.LengthMismatch.selector));
    s_token.batchSetAddressFrozen(users, freezeFlags);
  }

  function test_batchSetAddressFrozen_notAuthorized_revert() public {
    address alice = makeAddr("alice");
    address unauthorized = makeAddr("unauthorized");

    address[] memory users = new address[](1);
    users[0] = alice;
    bool[] memory freezeFlags = new bool[](1);
    freezeFlags[0] = true;

    vm.startPrank(unauthorized);
    _expectRejectedRevert(
      address(freezingList),
      "sender is not authorized",
      IToken.setAddressFrozen.selector,
      unauthorized,
      abi.encode(alice, true)
    );
    s_token.batchSetAddressFrozen(users, freezeFlags);
  }

  // --- batchFreezePartialTokens ---

  function test_batchFreezePartialTokens_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 150);
    s_token.mint(bob, 120);

    address[] memory users = new address[](2);
    users[0] = alice;
    users[1] = bob;
    uint256[] memory amounts = new uint256[](2);
    amounts[0] = 50;
    amounts[1] = 100;

    s_token.batchFreezePartialTokens(users, amounts);

    assertEq(s_token.getFrozenTokens(alice), 50);
    assertEq(s_token.getFrozenTokens(bob), 100);
  }

  function test_batchFreezePartialTokens_lengthMismatch_revert() public {
    address[] memory users = new address[](2);
    users[0] = makeAddr("alice");
    users[1] = makeAddr("bob");
    uint256[] memory amounts = new uint256[](1);
    amounts[0] = 50;

    vm.expectRevert(abi.encodeWithSelector(ComplianceTokenERC3643.LengthMismatch.selector));
    s_token.batchFreezePartialTokens(users, amounts);
  }

  function test_batchFreezePartialTokens_notAuthorized_revert() public {
    address alice = makeAddr("alice");
    address unauthorized = makeAddr("unauthorized");

    s_token.mint(alice, 150);

    address[] memory users = new address[](1);
    users[0] = alice;
    uint256[] memory amounts = new uint256[](1);
    amounts[0] = 50;

    vm.startPrank(unauthorized);
    _expectRejectedRevert(
      address(freezingList),
      "sender is not authorized",
      IToken.freezePartialTokens.selector,
      unauthorized,
      abi.encode(alice, uint256(50))
    );
    s_token.batchFreezePartialTokens(users, amounts);
  }

  // --- batchUnfreezePartialTokens ---

  function test_batchUnfreezePartialTokens_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 150);
    s_token.mint(bob, 120);
    s_token.freezePartialTokens(alice, 80);
    s_token.freezePartialTokens(bob, 60);

    address[] memory users = new address[](2);
    users[0] = alice;
    users[1] = bob;
    uint256[] memory amounts = new uint256[](2);
    amounts[0] = 30;
    amounts[1] = 40;

    s_token.batchUnfreezePartialTokens(users, amounts);

    assertEq(s_token.getFrozenTokens(alice), 50);
    assertEq(s_token.getFrozenTokens(bob), 20);
  }

  function test_batchUnfreezePartialTokens_lengthMismatch_revert() public {
    address[] memory users = new address[](2);
    users[0] = makeAddr("alice");
    users[1] = makeAddr("bob");
    uint256[] memory amounts = new uint256[](1);
    amounts[0] = 30;

    vm.expectRevert(abi.encodeWithSelector(ComplianceTokenERC3643.LengthMismatch.selector));
    s_token.batchUnfreezePartialTokens(users, amounts);
  }

  function test_batchUnfreezePartialTokens_notAuthorized_revert() public {
    address alice = makeAddr("alice");
    address unauthorized = makeAddr("unauthorized");

    s_token.mint(alice, 150);
    s_token.freezePartialTokens(alice, 80);

    address[] memory users = new address[](1);
    users[0] = alice;
    uint256[] memory amounts = new uint256[](1);
    amounts[0] = 30;

    vm.startPrank(unauthorized);
    _expectRejectedRevert(
      address(freezingList),
      "sender is not authorized",
      IToken.unfreezePartialTokens.selector,
      unauthorized,
      abi.encode(alice, uint256(30))
    );
    s_token.batchUnfreezePartialTokens(users, amounts);
  }
}

/// @notice Exposes TOKEN_VERSION for tests so version assertions stay aligned with bumps.
contract ComplianceTokenERC3643VersionRef is ComplianceTokenERC3643 {
  function tokenVersionExpected() external pure returns (string memory) {
    return TOKEN_VERSION;
  }
}
