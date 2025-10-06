// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {GrantorPolicy} from "@chainlink/policy-management/policies/GrantorPolicy.sol";
import {ERC20TransferExtractor} from "@chainlink/policy-management/extractors/ERC20TransferExtractor.sol";
import {MockToken} from "../helpers/MockToken.sol";
import {BaseProxyTest} from "../helpers/BaseProxyTest.sol";

contract GrantorPolicyTest is BaseProxyTest {
  PolicyEngine public policyEngine;
  GrantorPolicy public grantorPolicy;
  ERC20TransferExtractor public extractor;
  MockToken public token;
  address public deployer;
  uint256 public deployerKey;
  address public sender;
  address public recipient;
  uint256 public amount = 100;
  uint48 public expiresAt = uint48(block.timestamp + 1 days);

  function setUp() public {
    vm.warp(1737583804);

    (deployer, deployerKey) = makeAddrAndKey("deployer");
    sender = makeAddr("sender");
    recipient = makeAddr("recipient");
    expiresAt = uint48(block.timestamp + 1 days);

    vm.startPrank(deployer, deployer);

    policyEngine = _deployPolicyEngine(IPolicyEngine.PolicyResult.Allowed, deployer);

    token = MockToken(_deployMockToken(address(policyEngine)));

    extractor = new ERC20TransferExtractor();
    bytes32[] memory parameterOutputFormat = new bytes32[](3);
    parameterOutputFormat[0] = extractor.PARAM_FROM();
    parameterOutputFormat[1] = extractor.PARAM_TO();
    parameterOutputFormat[2] = extractor.PARAM_AMOUNT();

    GrantorPolicy grantorPolicyImpl = new GrantorPolicy();
    grantorPolicy = GrantorPolicy(_deployPolicy(address(grantorPolicyImpl), address(policyEngine), deployer, bytes("")));

    policyEngine.setExtractor(MockToken.transfer.selector, address(extractor));

    policyEngine.addPolicy(address(token), MockToken.transfer.selector, address(grantorPolicy), parameterOutputFormat);
  }

  function test_initialize_emitSignerAdded_succeeds() public {
    vm.startPrank(deployer, deployer);

    GrantorPolicy grantorPolicyImpl = new GrantorPolicy();
    vm.expectEmit();
    emit GrantorPolicy.SignerAdded(deployer);
    grantorPolicy = GrantorPolicy(_deployPolicy(address(grantorPolicyImpl), address(policyEngine), deployer, bytes("")));
  }

  function test_transfer_validSignature_succeeds() public {
    // tx data
    uint256 nonce = grantorPolicy.senderNonce(sender);
    GrantorPolicy.TransferInfo memory transferInfo =
      GrantorPolicy.TransferInfo({from: sender, to: recipient, amount: amount, nonce: nonce, expiresAt: expiresAt});

    // build context
    bytes32 digest = grantorPolicy.hash(transferInfo);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(deployerKey, digest);
    bytes memory signature = abi.encodePacked(r, s, v);
    GrantorPolicy.GrantorContext memory context =
      GrantorPolicy.GrantorContext({expiresAt: expiresAt, signature: signature});

    // transfer
    vm.startPrank(sender, sender);
    assertEq(token.balanceOf(recipient), 0);
    token.setContext(abi.encode(context));
    token.transfer(recipient, amount);
    assertEq(token.balanceOf(recipient), amount);

    // check nonce
    uint256 newNonce = grantorPolicy.senderNonce(sender);
    assertEq(newNonce, nonce + 1);
  }

  function test_transfer_signerNotAdded_fails() public {
    // tx data
    uint256 nonce = grantorPolicy.senderNonce(sender);
    GrantorPolicy.TransferInfo memory transferInfo =
      GrantorPolicy.TransferInfo({from: sender, to: recipient, amount: amount, nonce: nonce, expiresAt: expiresAt});

    // build context
    (, uint256 invalidKey) = makeAddrAndKey("invalidSigner");
    bytes32 digest = grantorPolicy.hash(transferInfo);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(invalidKey, digest);
    bytes memory signature = abi.encodePacked(r, s, v);
    GrantorPolicy.GrantorContext memory context =
      GrantorPolicy.GrantorContext({expiresAt: expiresAt, signature: signature});

    // transfer (should revert)
    vm.startPrank(sender, sender);
    token.setContext(abi.encode(context));
    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyRunRejected.selector, MockToken.transfer.selector, address(grantorPolicy)
      )
    );
    token.transfer(recipient, amount);

    // check nonce (should not change)
    uint256 newNonce = grantorPolicy.senderNonce(sender);
    assertEq(newNonce, nonce);
  }

  function test_transfer_invalidNonce_fails() public {
    // tx data
    uint256 nonce = type(uint256).max; // invalid nonce
    uint256 actualNonce = grantorPolicy.senderNonce(sender);
    GrantorPolicy.TransferInfo memory transferInfo =
      GrantorPolicy.TransferInfo({from: sender, to: recipient, amount: amount, nonce: nonce, expiresAt: expiresAt});

    // build context
    bytes32 digest = grantorPolicy.hash(transferInfo);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(deployerKey, digest);
    bytes memory signature = abi.encodePacked(r, s, v);
    GrantorPolicy.GrantorContext memory context =
      GrantorPolicy.GrantorContext({expiresAt: expiresAt, signature: signature});

    // transfer (should revert)
    vm.startPrank(sender, sender);
    token.setContext(abi.encode(context));
    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyRunRejected.selector, MockToken.transfer.selector, address(grantorPolicy)
      )
    );
    token.transfer(recipient, amount);
    token.transferWithContext(recipient, amount, abi.encode(context));

    // check nonce (should not change)
    uint256 newNonce = grantorPolicy.senderNonce(sender);
    assertEq(newNonce, actualNonce);
  }

  function test_transfer_expiredSignature_fails() public {
    // tx data
    uint256 nonce = grantorPolicy.senderNonce(sender);
    uint48 expiredDate = uint48(block.timestamp - 1 days); // expired
    GrantorPolicy.TransferInfo memory transferInfo =
      GrantorPolicy.TransferInfo({from: sender, to: recipient, amount: amount, nonce: nonce, expiresAt: expiredDate});

    // build context
    bytes32 digest = grantorPolicy.hash(transferInfo);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(deployerKey, digest);
    bytes memory signature = abi.encodePacked(r, s, v);
    GrantorPolicy.GrantorContext memory context =
      GrantorPolicy.GrantorContext({expiresAt: expiredDate, signature: signature});

    // transfer (should revert)
    vm.startPrank(sender, sender);
    token.setContext(abi.encode(context));
    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyRunRejected.selector, MockToken.transfer.selector, address(grantorPolicy)
      )
    );
    token.transfer(recipient, amount);
    token.transferWithContext(recipient, amount, abi.encode(context));

    // check nonce (should not change)
    uint256 newNonce = grantorPolicy.senderNonce(sender);
    assertEq(newNonce, nonce);
  }

  function test_transfer_invalidatedSignature_fails() public {
    // tx data
    uint256 nonce = grantorPolicy.senderNonce(sender);
    GrantorPolicy.TransferInfo memory transferInfo =
      GrantorPolicy.TransferInfo({from: sender, to: recipient, amount: amount, nonce: nonce, expiresAt: expiresAt});

    // build context
    bytes32 digest = grantorPolicy.hash(transferInfo);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(deployerKey, digest);
    bytes memory signature = abi.encodePacked(r, s, v);
    GrantorPolicy.GrantorContext memory context =
      GrantorPolicy.GrantorContext({expiresAt: expiresAt, signature: signature});

    vm.startPrank(sender, sender);

    // increment nonce to invalidate signature
    grantorPolicy.incrementNonce();

    // transfer
    token.setContext(abi.encode(context));
    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyRunRejected.selector, MockToken.transfer.selector, address(grantorPolicy)
      )
    );
    token.transfer(recipient, amount);
  }

  function test_addSigner_succeeds() public {
    // add new signer
    (address newSigner, uint256 newSignerKey) = makeAddrAndKey("newSigner");
    vm.startPrank(deployer, deployer);
    vm.expectEmit();
    emit GrantorPolicy.SignerAdded(newSigner);
    grantorPolicy.addSigner(newSigner);

    // tx data
    uint256 nonce = grantorPolicy.senderNonce(sender);
    GrantorPolicy.TransferInfo memory transferInfo =
      GrantorPolicy.TransferInfo({from: sender, to: recipient, amount: amount, nonce: nonce, expiresAt: expiresAt});

    // build context (sign with new signer key)
    bytes32 digest = grantorPolicy.hash(transferInfo);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(newSignerKey, digest);
    bytes memory signature = abi.encodePacked(r, s, v);
    GrantorPolicy.GrantorContext memory context =
      GrantorPolicy.GrantorContext({expiresAt: expiresAt, signature: signature});

    // transfer
    vm.startPrank(sender, sender);
    assertEq(token.balanceOf(recipient), 0);
    token.setContext(abi.encode(context));
    token.transfer(recipient, amount);
    assertEq(token.balanceOf(recipient), amount);

    // check nonce
    uint256 newNonce = grantorPolicy.senderNonce(sender);
    assertEq(newNonce, nonce + 1);
  }

  function test_addSigner_alreadyAdded_fails() public {
    // add deployer as signer (which is already a signer)
    vm.expectRevert("address is already a signer");
    grantorPolicy.addSigner(deployer);
  }

  function test_removeSigner_succeeds() public {
    // add new signer (and sanity check)
    (address newSigner, uint256 newSignerKey) = makeAddrAndKey("newSigner");
    vm.startPrank(deployer, deployer);
    vm.expectEmit();
    emit GrantorPolicy.SignerAdded(newSigner);
    grantorPolicy.addSigner(newSigner);

    // remove new signer
    vm.expectEmit();
    emit GrantorPolicy.SignerRemoved(newSigner);
    grantorPolicy.removeSigner(newSigner);

    // tx data
    uint256 nonce = grantorPolicy.senderNonce(sender);
    GrantorPolicy.TransferInfo memory transferInfo =
      GrantorPolicy.TransferInfo({from: sender, to: recipient, amount: amount, nonce: nonce, expiresAt: expiresAt});

    // build context (sign with new signer key)
    bytes32 digest = grantorPolicy.hash(transferInfo);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(newSignerKey, digest);
    bytes memory signature = abi.encodePacked(r, s, v);
    GrantorPolicy.GrantorContext memory context =
      GrantorPolicy.GrantorContext({expiresAt: expiresAt, signature: signature});

    // transfer (should revert)
    vm.startPrank(sender, sender);
    token.setContext(abi.encode(context));
    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyRunRejected.selector, MockToken.transfer.selector, address(grantorPolicy)
      )
    );
    token.transfer(recipient, amount);
  }

  function test_removeSigner_alreadyAdded_fails() public {
    // remove invalid signer (revert)
    (address newSigner,) = makeAddrAndKey("newSigner");
    vm.expectRevert("address is not signer");
    grantorPolicy.removeSigner(newSigner);
  }

  function test_incrementNonce_succeeds() public {
    vm.startPrank(sender, sender);

    // First increment - expect event with exact sender and nonce 1
    vm.expectEmit();
    emit GrantorPolicy.NonceIncremented(sender, 1);
    grantorPolicy.incrementNonce();
    vm.assertEq(grantorPolicy.senderNonce(sender), 1);

    // Second increment - expect event with exact sender and nonce 2
    vm.expectEmit();
    emit GrantorPolicy.NonceIncremented(sender, 2);
    grantorPolicy.incrementNonce();
    vm.assertEq(grantorPolicy.senderNonce(sender), 2);
  }
}
