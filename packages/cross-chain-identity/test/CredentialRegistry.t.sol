// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {ICredentialRegistry, CredentialRegistry} from "../src/CredentialRegistry.sol";
import {PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {BaseProxyTest} from "./helpers/BaseProxyTest.sol";

contract CredentialRegistryTest is BaseProxyTest {
  bytes32 public constant CREDENTIAL_KYC = keccak256("common.kyc");
  bytes32 public constant CREDENTIAL_ACCREDITED = keccak256("common.accredited");

  PolicyEngine internal s_policyEngine;
  CredentialRegistry internal s_credentialRegistry;

  address internal s_owner;

  function setUp() public {
    s_owner = makeAddr("owner");

    vm.startPrank(s_owner);

    s_policyEngine = _deployPolicyEngine(IPolicyEngine.PolicyResult.Allowed, address(this));
    s_credentialRegistry = _deployCredentialRegistry(address(s_policyEngine));
  }

  function test_registerCredential_success() public {
    bytes32 ccid = keccak256("account1");

    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYC, 0, "", "");
    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_ACCREDITED, 0, "", "");

    bytes32[] memory creds = s_credentialRegistry.getCredentialTypes(ccid);
    assert(creds.length == 2);
  }

  function test_registerCredentials_success() public {
    bytes32 ccid = keccak256("account1");

    bytes32[] memory credentialTypeIds = new bytes32[](2);
    bytes[] memory credentialDatas = new bytes[](2);

    credentialTypeIds[0] = CREDENTIAL_ACCREDITED;
    credentialDatas[0] = "ACCREDITED";

    credentialTypeIds[1] = CREDENTIAL_KYC;
    credentialDatas[1] = "KYC";

    s_credentialRegistry.registerCredentials(ccid, credentialTypeIds, 0, credentialDatas, "");

    bytes32[] memory creds = s_credentialRegistry.getCredentialTypes(ccid);
    assert(creds.length == 2);
  }

  function test_registerCredential_expired_revert() public {
    bytes32 ccid = keccak256("account1");

    vm.expectPartialRevert(ICredentialRegistry.InvalidCredentialConfiguration.selector);
    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYC, 1, "", "");
  }

  function test_removeCredential_success() public {
    bytes32 ccid = keccak256("account1");

    bytes32[] memory credentialTypeIds = new bytes32[](2);
    bytes[] memory credentialDatas = new bytes[](2);

    credentialTypeIds[0] = CREDENTIAL_ACCREDITED;
    credentialDatas[0] = "ACCREDITED";

    credentialTypeIds[1] = CREDENTIAL_KYC;
    credentialDatas[1] = "KYC";

    s_credentialRegistry.registerCredentials(ccid, credentialTypeIds, 0, credentialDatas, "");

    bytes32[] memory creds = s_credentialRegistry.getCredentialTypes(ccid);
    assert(creds.length == 2);

    s_credentialRegistry.removeCredential(ccid, credentialTypeIds[0], "");

    creds = s_credentialRegistry.getCredentialTypes(ccid);
    assert(creds.length == 1);
  }

  function test_removeCredential_notFound_failure() public {
    bytes32 ccid = keccak256("account_not_defined");

    bytes32[] memory creds = s_credentialRegistry.getCredentialTypes(ccid);
    assert(creds.length == 0);

    vm.expectRevert();
    s_credentialRegistry.removeCredential(ccid, bytes32(0), "");
  }

  function test_getCredential_success() public {
    bytes32 ccid = keccak256("account1");
    bytes memory expectedData = bytes("data");

    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYC, 0, expectedData, "");

    bytes memory cred_data = s_credentialRegistry.getCredential(ccid, CREDENTIAL_KYC).credentialData;

    assert(expectedData.length == cred_data.length);
    for (uint256 i = 0; i < cred_data.length; i++) {
      assert(cred_data[i] == expectedData[i]);
    }
  }

  function test_getCredential_notFound_failure() public {
    bytes32 ccid = keccak256("account1");
    bytes memory credentialData = bytes("data");

    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYC, 0, credentialData, "");

    vm.expectPartialRevert(ICredentialRegistry.CredentialNotFound.selector);
    s_credentialRegistry.getCredential(ccid, CREDENTIAL_ACCREDITED);
  }

  function test_getCredentials_success() public {
    bytes32 ccid = keccak256("account1");

    bytes32[] memory credentialTypeIds = new bytes32[](2);
    bytes[] memory credentialDatas = new bytes[](2);

    credentialTypeIds[0] = CREDENTIAL_ACCREDITED;
    credentialDatas[0] = "ACCREDITED";

    credentialTypeIds[1] = CREDENTIAL_KYC;
    credentialDatas[1] = "KYC";

    s_credentialRegistry.registerCredentials(ccid, credentialTypeIds, 0, credentialDatas, "");

    bytes32[] memory creds = s_credentialRegistry.getCredentialTypes(ccid);
    assert(creds.length == 2);

    ICredentialRegistry.Credential[] memory credentials = s_credentialRegistry.getCredentials(ccid, credentialTypeIds);

    assert(credentials.length == 2);
    assert(keccak256(credentials[0].credentialData) == keccak256(bytes("ACCREDITED")));
    assert(keccak256(credentials[1].credentialData) == keccak256(bytes("KYC")));
  }

  function test_getCredentials_notFound_failure() public {
    bytes32 ccid = keccak256("account1");
    bytes memory credentialData = bytes("data");

    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYC, 0, credentialData, "");

    bytes32[] memory credentialTypeIds = new bytes32[](2);
    credentialTypeIds[0] = CREDENTIAL_KYC;
    credentialTypeIds[1] = CREDENTIAL_ACCREDITED;

    vm.expectPartialRevert(ICredentialRegistry.CredentialNotFound.selector);
    s_credentialRegistry.getCredentials(ccid, credentialTypeIds);
  }

  function test_renewCredential_success() public {
    bytes32 ccid = keccak256("account1");

    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYC, uint40(block.timestamp + 1), "", "");
    vm.warp(block.timestamp + 10);

    bool validateBeforeRenewal = s_credentialRegistry.validate(ccid, CREDENTIAL_KYC, "");

    assert(validateBeforeRenewal == false);

    s_credentialRegistry.renewCredential(ccid, CREDENTIAL_KYC, uint40(block.timestamp + 20), "");

    bool validateAfterRenewal = s_credentialRegistry.validate(ccid, CREDENTIAL_KYC, "");
    assert(validateAfterRenewal == true);
  }

  function test_renewCredential_emitsEventWithPreviousExpiry() public {
    bytes32 ccid = keccak256("account1");
    uint40 initialExpiry = uint40(block.timestamp + 100);
    uint40 newExpiry = uint40(block.timestamp + 200);

    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYC, initialExpiry, "", "");

    vm.expectEmit();
    emit ICredentialRegistry.CredentialRenewed(ccid, CREDENTIAL_KYC, initialExpiry, newExpiry);

    s_credentialRegistry.renewCredential(ccid, CREDENTIAL_KYC, newExpiry, "");
  }

  function test_renewCredential_allowsShorteningCredential() public {
    bytes32 ccid = keccak256("account1");

    uint40 originalExpiry = uint40(block.timestamp + 100);
    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYC, originalExpiry, "", "");

    uint40 shorterExpiry = uint40(block.timestamp + 50);
    vm.expectEmit();
    emit ICredentialRegistry.CredentialRenewed(ccid, CREDENTIAL_KYC, originalExpiry, shorterExpiry);
    s_credentialRegistry.renewCredential(ccid, CREDENTIAL_KYC, shorterExpiry, "");

    ICredentialRegistry.Credential memory credential = s_credentialRegistry.getCredential(ccid, CREDENTIAL_KYC);
    assertEq(credential.expiresAt, shorterExpiry);

    s_credentialRegistry.renewCredential(ccid, CREDENTIAL_KYC, shorterExpiry, "");
  }

  function test_validateAll_success() public {
    bytes32 ccid = keccak256("account1");

    bytes32[] memory credentialTypeIds = new bytes32[](2);
    bytes[] memory credentialDatas = new bytes[](2);

    credentialTypeIds[0] = CREDENTIAL_ACCREDITED;
    credentialDatas[0] = "ACCREDITED";

    credentialTypeIds[1] = CREDENTIAL_KYC;
    credentialDatas[1] = "KYC";

    s_credentialRegistry.registerCredentials(ccid, credentialTypeIds, 0, credentialDatas, "");

    bool validateAllRes = s_credentialRegistry.validateAll(ccid, credentialTypeIds, "");
    assert(validateAllRes == true);
  }
}
