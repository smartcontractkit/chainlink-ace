// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ComplianceTokenERC20} from "../src/ComplianceTokenERC20.sol";
import {PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {IPolicy} from "@chainlink/policy-management/interfaces/IPolicy.sol";
import {OnlyOwnerPolicy} from "@chainlink/policy-management/policies/OnlyOwnerPolicy.sol";
import {OnlyAuthorizedSenderPolicy} from "@chainlink/policy-management/policies/OnlyAuthorizedSenderPolicy.sol";
import {VolumePolicy} from "@chainlink/policy-management/policies/VolumePolicy.sol";
import {BaseProxyTest} from "./helpers/BaseProxyTest.sol";
import {ComplianceTokenMintBurnExtractor} from
  "@chainlink/policy-management/extractors/ComplianceTokenMintBurnExtractor.sol";
import {ComplianceTokenFreezeUnfreezeExtractor} from
  "@chainlink/policy-management/extractors/ComplianceTokenFreezeUnfreezeExtractor.sol";
import {ComplianceTokenForceTransferExtractor} from
  "@chainlink/policy-management/extractors/ComplianceTokenForceTransferExtractor.sol";
import {ERC20TransferExtractor} from "@chainlink/policy-management/extractors/ERC20TransferExtractor.sol";

contract ComplianceTokenERC20Test is BaseProxyTest {
  PolicyEngine internal s_policyEngine;
  ComplianceTokenERC20 internal s_token;
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
    ComplianceTokenMintBurnExtractor mintBurnExtractor = new ComplianceTokenMintBurnExtractor();
    s_policyEngine.setExtractor(ComplianceTokenERC20.mint.selector, address(mintBurnExtractor));
    s_policyEngine.setExtractor(ComplianceTokenERC20.burn.selector, address(mintBurnExtractor));
    s_policyEngine.setExtractor(ComplianceTokenERC20.burnFrom.selector, address(mintBurnExtractor));
    ComplianceTokenFreezeUnfreezeExtractor freezeUnfreezeExtractor = new ComplianceTokenFreezeUnfreezeExtractor();
    s_policyEngine.setExtractor(ComplianceTokenERC20.freeze.selector, address(freezeUnfreezeExtractor));
    s_policyEngine.setExtractor(ComplianceTokenERC20.unfreeze.selector, address(freezeUnfreezeExtractor));
    s_policyEngine.setExtractor(
      ComplianceTokenERC20.forceTransfer.selector, address(new ComplianceTokenForceTransferExtractor())
    );

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

    s_token = _deployComplianceTokenERC20("Test Token", "TST", 18, address(s_policyEngine));

    bytes32[] memory volumeParams = new bytes32[](1);
    volumeParams[0] = mintBurnExtractor.PARAM_AMOUNT();

    // admin methods - onlyOwner
    s_policyEngine.addPolicy(
      address(s_token), ComplianceTokenERC20.forceTransfer.selector, address(onlyOwnerPolicy), new bytes32[](0)
    );
    // mint - onlyAuthorized - volume
    s_policyEngine.addPolicy(
      address(s_token), ComplianceTokenERC20.mint.selector, address(minterBurnerList), new bytes32[](0)
    );
    s_policyEngine.addPolicy(address(s_token), ComplianceTokenERC20.mint.selector, address(volumePolicy), volumeParams);
    // burn/burnFrom - onlyAuthorized
    s_policyEngine.addPolicy(
      address(s_token), ComplianceTokenERC20.burn.selector, address(minterBurnerList), new bytes32[](0)
    );
    s_policyEngine.addPolicy(
      address(s_token), ComplianceTokenERC20.burnFrom.selector, address(minterBurnerList), new bytes32[](0)
    );
    // freezing methods - onlyAuthorized
    s_policyEngine.addPolicy(
      address(s_token), ComplianceTokenERC20.freeze.selector, address(freezingList), new bytes32[](0)
    );
    s_policyEngine.addPolicy(
      address(s_token), ComplianceTokenERC20.unfreeze.selector, address(freezingList), new bytes32[](0)
    );
    // transfer methods - volume
    s_policyEngine.addPolicy(address(s_token), IERC20.transfer.selector, address(volumePolicy), volumeParams);
    s_policyEngine.addPolicy(address(s_token), IERC20.transferFrom.selector, address(volumePolicy), volumeParams);
  }

  function test_mint_success() public {
    address alice = makeAddr("alice");

    s_token.mint(alice, 110);

    assertEq(s_token.balanceOf(alice), 110);
    assertEq(s_token.totalSupply(), 110);
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
        ComplianceTokenERC20.mint.selector,
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
        ComplianceTokenERC20.mint.selector,
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
        ComplianceTokenERC20.mint.selector,
        address(minterBurnerList),
        "sender is not authorized"
      )
    );
    s_token.mint(alice, 10);
  }

  function test_burn_success() public {
    s_token.mint(s_bridge, 110);

    vm.stopPrank();
    vm.startPrank(s_bridge);

    s_token.burn(5);

    assertEq(s_token.balanceOf(s_bridge), 105);
    assertEq(s_token.totalSupply(), 105);
  }

  function test_burn_overBalance_revert() public {
    s_token.mint(s_bridge, 110);

    vm.stopPrank();
    vm.startPrank(s_bridge);

    vm.expectRevert("amount exceeds available balance");
    s_token.burn(111);
  }

  function test_burn_notAuthorized_failure() public {
    address alice = makeAddr("alice");

    s_token.mint(alice, 110);

    vm.stopPrank();
    vm.startPrank(alice);

    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyRunRejected.selector,
        ComplianceTokenERC20.burn.selector,
        address(minterBurnerList),
        "sender is not authorized"
      )
    );
    s_token.burn(111);
  }

  function test_burn_frozenBalance_revert() public {
    s_token.mint(s_bridge, 110);

    s_token.freeze(s_bridge, 60, "");

    vm.stopPrank();
    vm.startPrank(s_bridge);

    vm.expectRevert("amount exceeds available balance");
    s_token.burn(55);
  }

  function test_burnFrom_success() public {
    address alice = makeAddr("alice");

    s_token.mint(alice, 110);

    s_token.burnFrom(alice, 50);

    assertEq(s_token.balanceOf(alice), 60);
    assertEq(s_token.totalSupply(), 60);
  }

  function test_burnFrom_bridge_success() public {
    address alice = makeAddr("alice");
    s_token.mint(alice, 120);
    assertEq(s_token.balanceOf(alice), 120);

    vm.stopPrank();
    vm.startPrank(s_bridge);

    s_token.burnFrom(alice, 70);

    assertEq(s_token.balanceOf(alice), 50);
    assertEq(s_token.totalSupply(), 50);
  }

  function test_burnFrom_notAuthorized_failure() public {
    address alice = makeAddr("alice");
    s_token.mint(alice, 120);
    assertEq(s_token.balanceOf(alice), 120);

    vm.stopPrank();
    vm.startPrank(alice);

    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyRunRejected.selector,
        ComplianceTokenERC20.burnFrom.selector,
        address(minterBurnerList),
        "sender is not authorized"
      )
    );
    s_token.burnFrom(alice, 70);
  }

  function test_transfer_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 170);

    vm.stopPrank();
    vm.startPrank(alice);

    s_token.transfer(bob, 110);

    assertEq(s_token.balanceOf(alice), 60);
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

  function test_transferFrom_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address charlie = makeAddr("charlie");

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

    s_token.mint(alice, 170);

    vm.stopPrank();
    vm.startPrank(alice);

    s_token.approve(charlie, 110);

    vm.stopPrank();
    vm.startPrank(charlie);

    vm.expectRevert("ERC20: transfer amount exceeds allowance");
    s_token.transferFrom(alice, bob, 111);
  }

  function test_transferFrom_frozenBalance_revert() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address charlie = makeAddr("charlie");

    s_token.mint(alice, 120);

    s_token.freeze(alice, 110, "");

    vm.stopPrank();
    vm.startPrank(alice);

    s_token.approve(charlie, 101);

    vm.stopPrank();
    vm.startPrank(charlie);

    vm.expectRevert("amount exceeds available balance");
    s_token.transferFrom(alice, bob, 101);
  }

  function test_freeze_transferPartialFrozen_revert() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 170);
    s_token.freeze(alice, 110, "");

    vm.stopPrank();
    vm.startPrank(alice);

    vm.expectRevert("amount exceeds available balance");
    s_token.transfer(bob, 120);
  }

  function test_freeze_transferPartialUnfrozen_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 170);
    s_token.freeze(alice, 50, "");

    vm.stopPrank();
    vm.startPrank(alice);

    s_token.transfer(bob, 110);

    assertEq(s_token.balanceOf(alice), 60);
    assertEq(s_token.balanceOf(bob), 110);
  }

  function test_freeze_notAuthorized_failure() public {
    address alice = makeAddr("alice");

    s_token.mint(alice, 120);

    vm.startPrank(alice);
    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyRunRejected.selector,
        ComplianceTokenERC20.freeze.selector,
        address(freezingList),
        "sender is not authorized"
      )
    );
    s_token.freeze(alice, 100, "");
  }

  function test_unfreeze_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 110);
    s_token.freeze(alice, 5, "");

    vm.stopPrank();
    vm.startPrank(alice);

    vm.expectRevert("amount exceeds available balance");
    s_token.transfer(bob, 107);

    vm.stopPrank();
    vm.startPrank(s_owner);

    s_token.unfreeze(alice, 3, "");

    vm.stopPrank();
    vm.startPrank(alice);

    s_token.transfer(bob, 107);

    assertEq(s_token.balanceOf(alice), 3);
    assertEq(s_token.balanceOf(bob), 107);
  }

  function test_frozenUnfrozen_enforcer_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 120);

    vm.startPrank(s_enforcer);
    s_token.freeze(alice, 100, "");

    vm.stopPrank();
    vm.startPrank(alice);

    vm.expectRevert("amount exceeds available balance");
    s_token.transfer(bob, 110);

    vm.stopPrank();
    vm.startPrank(s_enforcer);

    s_token.unfreeze(alice, 100, "");

    vm.stopPrank();
    vm.startPrank(alice);

    s_token.transfer(bob, 110);
    assertEq(s_token.balanceOf(alice), 10);
    assertEq(s_token.balanceOf(bob), 110);
  }

  function test_unfreeze_notAuthorized_failure() public {
    address alice = makeAddr("alice");

    s_token.mint(alice, 120);
    s_token.freeze(alice, 60, "");

    vm.startPrank(alice);
    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyRunRejected.selector,
        ComplianceTokenERC20.unfreeze.selector,
        address(freezingList),
        "sender is not authorized"
      )
    );
    s_token.unfreeze(alice, 60, "");
  }

  function test_forceTransfer_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 170);

    s_token.forceTransfer(alice, bob, 60, "");

    assertEq(s_token.balanceOf(alice), 110);
    assertEq(s_token.balanceOf(bob), 60);
  }

  function test_forceTransfer_frozenBalance_success() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 170);

    s_token.freeze(alice, 60, "");

    s_token.forceTransfer(alice, bob, 140, "");

    assertEq(s_token.balanceOf(alice), 30);
    assertEq(s_token.balanceOf(bob), 140);
  }

  function test_forceTransfer_notOwner_revert() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    s_token.mint(alice, 110);

    vm.stopPrank();
    vm.startPrank(bob);

    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyRunRejected.selector,
        ComplianceTokenERC20.forceTransfer.selector,
        address(onlyOwnerPolicy),
        "caller is not the policy owner"
      )
    );
    s_token.forceTransfer(alice, bob, 60, "");
  }
}
