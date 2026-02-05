// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IIdentityRegistry} from "../src/interfaces/IIdentityRegistry.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {IdentityRegistry} from "../src/IdentityRegistry.sol";
import {PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {BaseProxyTest} from "./helpers/BaseProxyTest.sol";

contract IdentityRegistryTest is BaseProxyTest {
  PolicyEngine internal s_policyEngine;
  IdentityRegistry internal s_identityRegistry;

  address internal s_owner;

  function setUp() public {
    s_owner = makeAddr("owner");

    vm.startPrank(s_owner);

    s_policyEngine = _deployPolicyEngine(true, address(this));
    s_identityRegistry = _deployIdentityRegistry(address(s_policyEngine));
  }

  function test_registerIdentity_success() public {
    address account1 = makeAddr("account1");
    bytes32 ccid = keccak256("account1");

    s_identityRegistry.registerIdentity(ccid, account1, "");
    bytes32 retrievedCcid = s_identityRegistry.getIdentity(account1);
    assert(ccid == retrievedCcid);
  }

  function test_registerIdentities_success() public {
    bytes32 investorCCID = keccak256("investor_x");
    bytes32[] memory ccids = new bytes32[](2);
    ccids[0] = investorCCID;
    ccids[1] = investorCCID;

    address[] memory inputAccounts = new address[](2);
    inputAccounts[0] = makeAddr("account1_for_investor_x");
    inputAccounts[1] = makeAddr("account2_for_investor_x");
    s_identityRegistry.registerIdentities(ccids, inputAccounts, "");

    bytes32 retrievedCcid1 = s_identityRegistry.getIdentity(inputAccounts[0]);
    bytes32 retrievedCcid2 = s_identityRegistry.getIdentity(inputAccounts[1]);

    assert(ccids[0] == retrievedCcid1);
    assert(ccids[1] == retrievedCcid2);

    address[] memory outputAccounts = s_identityRegistry.getAccounts(investorCCID);
    assert(outputAccounts.length == 2);
  }

  function test_registerIdentities_duplicated_failure() public {
    bytes32[] memory ccids = new bytes32[](2);
    address account1 = makeAddr("account1");
    bytes32 ccid1 = keccak256("account1");
    ccids[0] = ccid1;
    ccids[1] = ccid1;

    address[] memory inputAccounts = new address[](2);
    inputAccounts[0] = account1;
    inputAccounts[1] = account1;

    bytes memory expectedRevertError =
      abi.encodeWithSignature("IdentityAlreadyRegistered(bytes32,address)", ccid1, account1);

    vm.expectRevert(expectedRevertError);
    s_identityRegistry.registerIdentities(ccids, inputAccounts, "");
  }

  function test_registerIdentity_ZeroCcid_failure() public {
    address account1 = makeAddr("account1");
    bytes32 ccid = bytes32(0);

    vm.expectRevert(
      abi.encodeWithSelector(IIdentityRegistry.InvalidIdentityConfiguration.selector, "CCID cannot be empty")
    );
    s_identityRegistry.registerIdentity(ccid, account1, "");
  }

  function test_removeIdentity_success() public {
    address account1 = makeAddr("account1");
    bytes32 ccid = keccak256("account1");

    s_identityRegistry.registerIdentity(ccid, account1, "");
    bytes32 retrievedCcid = s_identityRegistry.getIdentity(account1);
    assert(ccid == retrievedCcid);

    s_identityRegistry.removeIdentity(ccid, account1, "");
    bytes32 retrievedCcidAfterRemoval = s_identityRegistry.getIdentity(account1);
    assert(retrievedCcidAfterRemoval == bytes32(0));
  }

  function test_removeIdentity_notFound_failure() public {
    address account1 = makeAddr("account1");
    bytes32 ccid = keccak256("account1");

    bytes32 retrievedCcid = s_identityRegistry.getIdentity(account1);
    assert(bytes32(0) == retrievedCcid);

    vm.expectRevert();
    s_identityRegistry.removeIdentity(ccid, account1, "");
  }

  function test_removeIdentity_multipleAccounts_removeFirst() public {
    bytes32 ccid = keccak256("investor_x");
    address account1 = makeAddr("account1");
    address account2 = makeAddr("account2");
    address account3 = makeAddr("account3");

    // Register three accounts
    s_identityRegistry.registerIdentity(ccid, account1, "");
    s_identityRegistry.registerIdentity(ccid, account2, "");
    s_identityRegistry.registerIdentity(ccid, account3, "");

    // Verify all registered
    address[] memory accounts = s_identityRegistry.getAccounts(ccid);
    assertEq(accounts.length, 3);

    // Remove first account
    s_identityRegistry.removeIdentity(ccid, account1, "");

    // Verify removal
    assertEq(s_identityRegistry.getIdentity(account1), bytes32(0));
    accounts = s_identityRegistry.getAccounts(ccid);
    assertEq(accounts.length, 2);

    // Verify remaining accounts are still valid
    assertEq(s_identityRegistry.getIdentity(account2), ccid);
    assertEq(s_identityRegistry.getIdentity(account3), ccid);
  }

  function test_removeIdentity_multipleAccounts_removeMiddle() public {
    bytes32 ccid = keccak256("investor_x");
    address account1 = makeAddr("account1");
    address account2 = makeAddr("account2");
    address account3 = makeAddr("account3");

    // Register three accounts
    s_identityRegistry.registerIdentity(ccid, account1, "");
    s_identityRegistry.registerIdentity(ccid, account2, "");
    s_identityRegistry.registerIdentity(ccid, account3, "");

    // Remove middle account
    s_identityRegistry.removeIdentity(ccid, account2, "");

    // Verify removal
    assertEq(s_identityRegistry.getIdentity(account2), bytes32(0));
    address[] memory accounts = s_identityRegistry.getAccounts(ccid);
    assertEq(accounts.length, 2);

    // Verify remaining accounts are still valid
    assertEq(s_identityRegistry.getIdentity(account1), ccid);
    assertEq(s_identityRegistry.getIdentity(account3), ccid);
  }

  function test_removeIdentity_multipleAccounts_removeLast() public {
    bytes32 ccid = keccak256("investor_x");
    address account1 = makeAddr("account1");
    address account2 = makeAddr("account2");
    address account3 = makeAddr("account3");

    // Register three accounts
    s_identityRegistry.registerIdentity(ccid, account1, "");
    s_identityRegistry.registerIdentity(ccid, account2, "");
    s_identityRegistry.registerIdentity(ccid, account3, "");

    // Remove last account
    s_identityRegistry.removeIdentity(ccid, account3, "");

    // Verify removal
    assertEq(s_identityRegistry.getIdentity(account3), bytes32(0));
    address[] memory accounts = s_identityRegistry.getAccounts(ccid);
    assertEq(accounts.length, 2);

    // Verify remaining accounts are still valid
    assertEq(s_identityRegistry.getIdentity(account1), ccid);
    assertEq(s_identityRegistry.getIdentity(account2), ccid);
  }

  function test_removeIdentity_multipleAccounts_removeAll() public {
    bytes32 ccid = keccak256("investor_x");
    address account1 = makeAddr("account1");
    address account2 = makeAddr("account2");
    address account3 = makeAddr("account3");

    // Register three accounts
    s_identityRegistry.registerIdentity(ccid, account1, "");
    s_identityRegistry.registerIdentity(ccid, account2, "");
    s_identityRegistry.registerIdentity(ccid, account3, "");

    // Remove all accounts one by one
    s_identityRegistry.removeIdentity(ccid, account2, "");
    s_identityRegistry.removeIdentity(ccid, account1, "");
    s_identityRegistry.removeIdentity(ccid, account3, "");

    // Verify all removed
    assertEq(s_identityRegistry.getIdentity(account1), bytes32(0));
    assertEq(s_identityRegistry.getIdentity(account2), bytes32(0));
    assertEq(s_identityRegistry.getIdentity(account3), bytes32(0));

    address[] memory accounts = s_identityRegistry.getAccounts(ccid);
    assertEq(accounts.length, 0);
  }

  function test_removeIdentity_alreadyRemoved_failure() public {
    bytes32 ccid = keccak256("investor_x");
    address account1 = makeAddr("account1");

    s_identityRegistry.registerIdentity(ccid, account1, "");
    s_identityRegistry.removeIdentity(ccid, account1, "");

    // Try to remove again
    vm.expectRevert(abi.encodeWithSelector(IIdentityRegistry.IdentityNotFound.selector, ccid, account1));
    s_identityRegistry.removeIdentity(ccid, account1, "");
  }

  function test_removeIdentity_largeNumberOfAccounts_gasEfficiency() public {
    bytes32 ccid = keccak256("investor_x");
    uint256 numAccounts = 100;
    address[] memory accounts = new address[](numAccounts);

    // Register many accounts
    for (uint256 i = 0; i < numAccounts; i++) {
      accounts[i] = makeAddr(string(abi.encodePacked("account", i)));
      s_identityRegistry.registerIdentity(ccid, accounts[i], "");
    }

    // Remove an account from the middle - should be O(1) regardless of array size
    uint256 gasStart = gasleft();
    s_identityRegistry.removeIdentity(ccid, accounts[50], "");
    uint256 gasUsed = gasStart - gasleft();

    // Verify removal
    assertEq(s_identityRegistry.getIdentity(accounts[50]), bytes32(0));
    address[] memory remainingAccounts = s_identityRegistry.getAccounts(ccid);
    assertEq(remainingAccounts.length, numAccounts - 1);

    // Gas should be relatively constant (not proportional to array size)
    // This is just a sanity check - actual gas limit would prevent unbounded loops
    assertTrue(gasUsed < 100000, "Gas usage should be bounded");
  }
}
