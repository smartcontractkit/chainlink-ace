// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

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
}
