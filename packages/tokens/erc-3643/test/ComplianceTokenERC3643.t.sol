// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IToken} from "../../../vendor/erc-3643/token/IToken.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {ComplianceTokenERC3643} from "../src/ComplianceTokenERC3643.sol";
import {PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {IPolicy} from "@chainlink/policy-management/interfaces/IPolicy.sol";
import {OnlyOwnerPolicy} from "@chainlink/policy-management/policies/OnlyOwnerPolicy.sol";
import {ExpectedContextPolicy} from "./helpers/ExpectedContextPolicy.sol";
import {BaseProxyTest} from "./helpers/BaseProxyTest.sol";
import {OnlyAuthorizedSenderPolicy} from "@chainlink/policy-management/policies/OnlyAuthorizedSenderPolicy.sol";
import {VolumePolicy} from "@chainlink/policy-management/policies/VolumePolicy.sol";
import {ERC3643MintBurnExtractor} from "@chainlink/policy-management/extractors/ERC3643MintBurnExtractor.sol";
import {ERC3643FreezeUnfreezeExtractor} from
  "@chainlink/policy-management/extractors/ERC3643FreezeUnfreezeExtractor.sol";
import {ERC3643ForcedTransferExtractor} from
  "@chainlink/policy-management/extractors/ERC3643ForcedTransferExtractor.sol";
import {ERC20TransferExtractor} from "@chainlink/policy-management/extractors/ERC20TransferExtractor.sol";
import {ERC3643SetAddressFrozenExtractor} from
  "@chainlink/policy-management/extractors/ERC3643SetAddressFrozenExtractor.sol";

contract ComplianceTokenERC3643Test is BaseProxyTest {
  PolicyEngine internal s_policyEngine;
  ComplianceTokenERC3643 internal s_token;
  address internal s_owner;
  address internal s_bridge;
  address internal s_enforcer;
  OnlyOwnerPolicy internal onlyOwnerPolicy;
  OnlyAuthorizedSenderPolicy internal minterBurnerList;
  OnlyAuthorizedSenderPolicy internal freezingList;
  VolumePolicy internal volumePolicy;

  function setUp() public {
    s_owner = makeAddr("owner");
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
    OnlyOwnerPolicy onlyOwnerPolicyImpl = new OnlyOwnerPolicy();
    onlyOwnerPolicy =
      OnlyOwnerPolicy(_deployPolicy(address(onlyOwnerPolicyImpl), address(s_policyEngine), s_owner, new bytes(0)));
    // to protect mint/burn with admin list
    OnlyAuthorizedSenderPolicy minterBurnerListImpl = new OnlyAuthorizedSenderPolicy();
    minterBurnerList = OnlyAuthorizedSenderPolicy(
      _deployPolicy(address(minterBurnerListImpl), address(s_policyEngine), s_owner, new bytes(0))
    );
    minterBurnerList.authorizeSender(s_owner);
    minterBurnerList.authorizeSender(s_bridge);
    // to protect freezing features with admin list
    OnlyAuthorizedSenderPolicy freezingListImpl = new OnlyAuthorizedSenderPolicy();
    freezingList = OnlyAuthorizedSenderPolicy(
      _deployPolicy(address(freezingListImpl), address(s_policyEngine), s_owner, new bytes(0))
    );
    freezingList.authorizeSender(s_owner);
    freezingList.authorizeSender(s_enforcer);
    // to enforce transaction limits
    VolumePolicy volumePolicyImpl = new VolumePolicy();
    volumePolicy =
      VolumePolicy(_deployPolicy(address(volumePolicyImpl), address(s_policyEngine), s_owner, abi.encode(100, 200)));

    s_token = _deployComplianceTokenERC3643("Test Token", "TST", 18, address(s_policyEngine));

    bytes32[] memory volumeParams = new bytes32[](1);
    volumeParams[0] = mintBurnExtractor.PARAM_AMOUNT();

    // admin methods - onlyOwner
    s_policyEngine.addPolicy(address(s_token), IToken.setName.selector, address(onlyOwnerPolicy), new bytes32[](0));
    s_policyEngine.addPolicy(address(s_token), IToken.setSymbol.selector, address(onlyOwnerPolicy), new bytes32[](0));
    s_policyEngine.addPolicy(address(s_token), IToken.pause.selector, address(onlyOwnerPolicy), new bytes32[](0));
    s_policyEngine.addPolicy(address(s_token), IToken.unpause.selector, address(onlyOwnerPolicy), new bytes32[](0));
    s_policyEngine.addPolicy(
      address(s_token), IToken.forcedTransfer.selector, address(onlyOwnerPolicy), new bytes32[](0)
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
    assertEq(s_token.name(), "Test Token");
    assertEq(s_token.symbol(), "TST");
    assertEq(s_token.decimals(), 18);
    assertEq(s_token.onchainID(), address(0));
    assertEq(s_token.version(), "1.0.0");

    s_token.setName("New Name");
    s_token.setSymbol("NME");

    assertEq(s_token.name(), "New Name");
    assertEq(s_token.symbol(), "NME");
  }

  function test_token_name_notOwner_failure() public {
    vm.startPrank(s_bridge);

    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyRunRejected.selector,
        IToken.setName.selector,
        address(onlyOwnerPolicy),
        "caller is not the policy owner"
      )
    );
    s_token.setName("New Name");
  }

  function test_token_symbol_notOwner_failure() public {
    vm.startPrank(s_bridge);

    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyRunRejected.selector,
        IToken.setSymbol.selector,
        address(onlyOwnerPolicy),
        "caller is not the policy owner"
      )
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
    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyRunRejected.selector,
        IToken.mint.selector,
        address(expectedContextPolicy),
        "context does not match expected value"
      )
    );
    s_token.mint(alice, 110);
  }

  function test_mint_bridge_success() public {
    address alice = makeAddr("alice");

    vm.stopPrank();
    vm.startPrank(s_bridge);
    s_token.mint(alice, 120);

    assertEq(s_token.balanceOf(alice), 120);
    assertEq(s_token.totalSupply(), 120);
  }

  function test_mint_over_failure() public {
    address alice = makeAddr("alice");

    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyRunRejected.selector,
        IToken.mint.selector,
        address(volumePolicy),
        "amount outside allowed volume limits"
      )
    );
    s_token.mint(alice, 220);
  }

  function test_mint_under_failure() public {
    address alice = makeAddr("alice");

    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyRunRejected.selector,
        IToken.mint.selector,
        address(volumePolicy),
        "amount outside allowed volume limits"
      )
    );
    s_token.mint(alice, 50);
  }

  function test_mint_notAuthorized_revert() public {
    address alice = makeAddr("alice");

    vm.stopPrank();
    vm.startPrank(alice);

    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyRunRejected.selector,
        IToken.mint.selector,
        address(minterBurnerList),
        "sender is not authorized"
      )
    );
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

    vm.stopPrank();
    vm.startPrank(s_bridge);

    s_token.burn(alice, 70);

    assertEq(s_token.balanceOf(alice), 50);
    assertEq(s_token.totalSupply(), 50);
  }

  function test_burn_notAuthorized_failure() public {
    address alice = makeAddr("alice");
    s_token.mint(alice, 120);
    assertEq(s_token.balanceOf(alice), 120);

    vm.stopPrank();
    vm.startPrank(alice);

    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyRunRejected.selector,
        IToken.burn.selector,
        address(minterBurnerList),
        "sender is not authorized"
      )
    );
    s_token.burn(alice, 70);
  }

  function test_transfer_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 120);

    vm.stopPrank();
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

    vm.stopPrank();
    vm.startPrank(alice);

    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyRunRejected.selector,
        IERC20.transfer.selector,
        address(volumePolicy),
        "amount outside allowed volume limits"
      )
    );
    s_token.transfer(bob, 210);
  }

  function test_transfer_under_failure() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 120);

    vm.stopPrank();
    vm.startPrank(alice);

    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyRunRejected.selector,
        IERC20.transfer.selector,
        address(volumePolicy),
        "amount outside allowed volume limits"
      )
    );
    s_token.transfer(bob, 50);
  }

  function test_transfer_paused_revert() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 120);

    s_token.pause();
    assertEq(s_token.paused(), true);

    vm.stopPrank();
    vm.startPrank(alice);

    vm.expectRevert("Pausable: paused");
    s_token.transfer(bob, 110);
  }

  function test_transfer_pause_notOwner_revert() public {
    address alice = makeAddr("alice");
    vm.startPrank(alice);

    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyRunRejected.selector,
        IToken.pause.selector,
        address(onlyOwnerPolicy),
        "caller is not the policy owner"
      )
    );
    s_token.pause();
  }

  function test_transfer_pausedUnpaused_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 120);

    s_token.pause();
    assertEq(s_token.paused(), true);

    s_token.unpause();
    assertEq(s_token.paused(), false);

    vm.stopPrank();
    vm.startPrank(alice);

    s_token.transfer(bob, 110);
    assertEq(s_token.balanceOf(alice), 10);
    assertEq(s_token.balanceOf(bob), 110);
  }

  function test_transfer_unpaused_notOwner_failure() public {
    address alice = makeAddr("alice");
    s_token.pause();
    assertEq(s_token.paused(), true);

    vm.stopPrank();
    vm.startPrank(alice);

    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyRunRejected.selector,
        IToken.unpause.selector,
        address(onlyOwnerPolicy),
        "caller is not the policy owner"
      )
    );
    s_token.unpause();
  }

  function test_transfer_frozenUnfrozen_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 120);

    s_token.setAddressFrozen(alice, true);
    assertEq(s_token.isFrozen(alice), true);

    vm.stopPrank();
    vm.startPrank(alice);

    vm.expectRevert("wallet is frozen");
    s_token.transfer(bob, 110);

    vm.stopPrank();
    vm.startPrank(s_owner);

    s_token.setAddressFrozen(alice, false);
    assertEq(s_token.isFrozen(alice), false);

    vm.stopPrank();
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

    vm.stopPrank();
    vm.startPrank(alice);

    vm.expectRevert("wallet is frozen");
    s_token.transfer(bob, 110);

    vm.stopPrank();
    vm.startPrank(s_enforcer);

    s_token.setAddressFrozen(alice, false);
    assertEq(s_token.isFrozen(alice), false);

    vm.stopPrank();
    vm.startPrank(alice);

    s_token.transfer(bob, 110);
    assertEq(s_token.balanceOf(alice), 10);
    assertEq(s_token.balanceOf(bob), 110);
  }

  function test_frozen_notAuthorized_failure() public {
    address alice = makeAddr("alice");

    s_token.mint(alice, 120);

    vm.startPrank(alice);
    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyRunRejected.selector,
        IToken.setAddressFrozen.selector,
        address(freezingList),
        "sender is not authorized"
      )
    );
    s_token.setAddressFrozen(alice, true);
  }

  function test_transferFrom_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address charlie = makeAddr("charlie");

    s_token.mint(alice, 199);

    vm.stopPrank();
    vm.startPrank(alice);

    s_token.approve(charlie, 110);

    vm.stopPrank();
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

    vm.stopPrank();
    vm.startPrank(alice);

    s_token.approve(charlie, 50);
    s_token.increaseAllowance(charlie, 60);
    assertEq(s_token.allowance(alice, charlie), 110);

    vm.stopPrank();
    vm.startPrank(charlie);

    s_token.transferFrom(alice, bob, 110);

    assertEq(s_token.balanceOf(alice), 40);
    assertEq(s_token.balanceOf(bob), 110);
  }

  function test_approve_paused_revert() public {
    address alice = makeAddr("alice");
    address charlie = makeAddr("charlie");

    s_token.mint(alice, 110);
    s_token.pause();

    vm.stopPrank();
    vm.startPrank(alice);

    vm.expectRevert("Pausable: paused");
    s_token.approve(charlie, 5);
  }

  function test_transferFrom_paused_revert() public {
    address alice = makeAddr("alice");
    address charlie = makeAddr("charlie");

    s_token.mint(alice, 150);

    vm.stopPrank();
    vm.startPrank(alice);

    s_token.approve(charlie, 50);

    vm.stopPrank();
    vm.startPrank(s_owner);
    s_token.pause();

    vm.stopPrank();
    vm.startPrank(alice);

    vm.expectRevert("Pausable: paused");
    s_token.approve(charlie, 60);
  }

  function test_transferFrom_insufficientAllowance_revert() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address charlie = makeAddr("charlie");

    s_token.mint(alice, 150);

    vm.stopPrank();
    vm.startPrank(alice);

    s_token.approve(charlie, 50);

    vm.stopPrank();
    vm.startPrank(charlie);

    vm.expectRevert(); // panic: arithmetic underflow or overflow
    s_token.transferFrom(alice, bob, 110);
  }

  function test_transferFrom_decreaseAllowance_revert() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address charlie = makeAddr("charlie");

    s_token.mint(alice, 150);

    vm.stopPrank();
    vm.startPrank(alice);

    s_token.approve(charlie, 110);
    s_token.decreaseAllowance(charlie, 20);

    vm.stopPrank();
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

    vm.stopPrank();
    vm.startPrank(alice);

    s_token.approve(charlie, 50);

    vm.stopPrank();
    vm.startPrank(charlie);

    vm.expectRevert("Insufficient Balance");
    s_token.transferFrom(alice, bob, 110);
  }

  function test_transfer_frozenBalance_revert() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 120);
    s_token.freezePartialTokens(alice, 50);

    vm.stopPrank();
    vm.startPrank(alice);

    vm.expectRevert("Insufficient Balance");
    s_token.transfer(bob, 110);
  }

  function test_transfer_partialUnfrozen_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 120);
    s_token.freezePartialTokens(alice, 10);

    vm.stopPrank();
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

    vm.stopPrank();
    vm.startPrank(alice);

    s_token.transfer(bob, 105);

    assertEq(s_token.balanceOf(alice), 15);
    assertEq(s_token.balanceOf(bob), 105);
  }

  function test_transfer_partialFreeze_notAuthorized_failure() public {
    address alice = makeAddr("alice");

    s_token.mint(alice, 120);
    vm.startPrank(alice);
    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyRunRejected.selector,
        IToken.freezePartialTokens.selector,
        address(freezingList),
        "sender is not authorized"
      )
    );
    s_token.freezePartialTokens(alice, 10);
  }

  function test_transfer_unfreezeBalance_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 120);
    s_token.freezePartialTokens(alice, 50);
    assertEq(s_token.getFrozenTokens(alice), 50);

    vm.stopPrank();
    vm.startPrank(alice);

    vm.expectRevert("Insufficient Balance");
    s_token.transfer(bob, 110);

    vm.stopPrank();
    vm.startPrank(s_owner);

    s_token.unfreezePartialTokens(alice, 40);
    assertEq(s_token.getFrozenTokens(alice), 10);

    vm.stopPrank();
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
    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyRunRejected.selector,
        IToken.unfreezePartialTokens.selector,
        address(freezingList),
        "sender is not authorized"
      )
    );
    s_token.unfreezePartialTokens(alice, 10);
  }

  function test_forcedTransfer_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 110);

    s_token.forcedTransfer(alice, bob, 60);

    assertEq(s_token.balanceOf(alice), 50);
    assertEq(s_token.balanceOf(bob), 60);
  }

  function test_forcedTransfer_frozenBalance_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 150);

    s_token.freezePartialTokens(alice, 90);

    s_token.forcedTransfer(alice, bob, 90);

    assertEq(s_token.balanceOf(alice), 60);
    assertEq(s_token.balanceOf(bob), 90);
  }

  function test_forcedTransfer_notOwner_revert() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 150);

    vm.stopPrank();
    vm.startPrank(bob);

    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyRunRejected.selector,
        IToken.forcedTransfer.selector,
        address(onlyOwnerPolicy),
        "caller is not the policy owner"
      )
    );
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
}
