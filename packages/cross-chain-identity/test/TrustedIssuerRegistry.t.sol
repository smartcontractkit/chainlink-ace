// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {ITrustedIssuerRegistry} from "../src/interfaces/ITrustedIssuerRegistry.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {TrustedIssuerRegistry} from "../src/TrustedIssuerRegistry.sol";
import {PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {BaseProxyTest} from "./helpers/BaseProxyTest.sol";

contract TrustedIssuerRegistryTest is BaseProxyTest {
  PolicyEngine internal s_policyEngine;
  TrustedIssuerRegistry internal s_trustedIssuerRegistry;
  address internal s_owner;

  function setUp() public {
    s_owner = makeAddr("owner");

    vm.startPrank(s_owner);
    s_policyEngine = _deployPolicyEngine(true, address(this));
    s_trustedIssuerRegistry = _deployTrustedIssuerRegistry(address(s_policyEngine));
    vm.stopPrank();
  }

  // -------------------------
  // Add trusted issuer
  // -------------------------

  function test_addTrustedIssuer_success() public {
    string memory issuerId = "did:example:issuer1";
    bytes32 didHash = keccak256(abi.encodePacked(issuerId));

    s_trustedIssuerRegistry.addTrustedIssuer(issuerId, "");

    bool isTrusted = s_trustedIssuerRegistry.isTrustedIssuer(issuerId);
    assertTrue(isTrusted);

    bytes32[] memory issuers = s_trustedIssuerRegistry.getTrustedIssuers();
    assertEq(issuers.length, 1);
    assertEq(issuers[0], didHash);
  }

  function test_addTrustedIssuer_emptyDid_failure() public {
    vm.expectRevert("issuerId cannot be empty");
    s_trustedIssuerRegistry.addTrustedIssuer("", "");
  }

  function test_addTrustedIssuer_duplicate_failure() public {
    string memory issuerId = "did:example:issuer1";

    s_trustedIssuerRegistry.addTrustedIssuer(issuerId, "");

    vm.expectRevert("Issuer already trusted");
    s_trustedIssuerRegistry.addTrustedIssuer(issuerId, "");
  }

  // -------------------------
  // Remove trusted issuer
  // -------------------------

  function test_removeTrustedIssuer_success() public {
    string memory issuerId = "did:example:issuer1";

    s_trustedIssuerRegistry.addTrustedIssuer(issuerId, "");
    assertTrue(s_trustedIssuerRegistry.isTrustedIssuer(issuerId));

    s_trustedIssuerRegistry.removeTrustedIssuer(issuerId, "");

    assertFalse(s_trustedIssuerRegistry.isTrustedIssuer(issuerId));

    bytes32[] memory issuers = s_trustedIssuerRegistry.getTrustedIssuers();
    assertEq(issuers.length, 0);
  }

  function test_removeTrustedIssuer_notTrusted_failure() public {
    string memory issuerId = "did:example:nonexistent";

    vm.expectRevert("Issuer not trusted");
    s_trustedIssuerRegistry.removeTrustedIssuer(issuerId, "");
  }

  // -------------------------
  // List management behavior
  // -------------------------

  function test_multipleIssuers_addAndRemove_listUpdatedCorrectly() public {
    string memory did1 = "did:example:issuer1";
    string memory did2 = "did:example:issuer2";
    string memory did3 = "did:example:issuer3";

    s_trustedIssuerRegistry.addTrustedIssuer(did1, "");
    s_trustedIssuerRegistry.addTrustedIssuer(did2, "");
    s_trustedIssuerRegistry.addTrustedIssuer(did3, "");

    bytes32[] memory beforeRemoval = s_trustedIssuerRegistry.getTrustedIssuers();
    assertEq(beforeRemoval.length, 3);

    s_trustedIssuerRegistry.removeTrustedIssuer(did2, "");

    bytes32[] memory afterRemoval = s_trustedIssuerRegistry.getTrustedIssuers();
    assertEq(afterRemoval.length, 2);

    bytes32 hash1 = keccak256(abi.encodePacked(did1));
    bytes32 hash3 = keccak256(abi.encodePacked(did3));

    assertTrue(afterRemoval[0] == hash1 || afterRemoval[1] == hash1);
    assertTrue(afterRemoval[0] == hash3 || afterRemoval[1] == hash3);
  }

  // -------------------------
  // View functions
  // -------------------------

  function test_isTrustedIssuer_returnsFalseWhenNotAdded() public {
    string memory issuerId = "did:example:nonexistent";
    bool isTrusted = s_trustedIssuerRegistry.isTrustedIssuer(issuerId);
    assertFalse(isTrusted);
  }

  function test_getTrustedIssuers_emptyInitially() public {
    bytes32[] memory issuers = s_trustedIssuerRegistry.getTrustedIssuers();
    assertEq(issuers.length, 0);
  }
}
