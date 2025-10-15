// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {ICredentialRequirements} from "../src/interfaces/ICredentialRequirements.sol";
import {ICredentialRegistry} from "../src/interfaces/ICredentialRegistry.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {IdentityRegistry} from "../src/IdentityRegistry.sol";
import {CredentialRegistry} from "../src/CredentialRegistry.sol";
import {CredentialRegistryIdentityValidator} from "../src/CredentialRegistryIdentityValidator.sol";
import {PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {MockCredentialDataValidator} from "./helpers/MockCredentialDataValidator.sol";
import {MockCredentialRegistryReverting} from "./helpers/MockCredentialRegistryReverting.sol";
import {BaseProxyTest} from "./helpers/BaseProxyTest.sol";

contract CredentialRegistryIdentityValidatorTest is BaseProxyTest {
  bytes32 public constant REQUIREMENT_KYC = keccak256("KYC");
  bytes32 public constant REQUIREMENT_ACCREDITED = keccak256("ACCREDITED");
  bytes32 public constant CREDENTIAL_KYC = keccak256("common.kyc");
  bytes32 public constant CREDENTIAL_ACCREDITED = keccak256("common.accredited");
  bytes32 public constant CREDENTIAL_INVALID_NATIONALITY = keccak256("common.invalid.nationality");

  bytes32[] internal s_credentials_kyc;
  bytes32[] internal s_credentials_accredited;
  bytes32[] internal s_credentials_invalid_nationality;

  PolicyEngine internal s_policyEngine;
  IdentityRegistry internal s_identityRegistry;
  CredentialRegistry internal s_credentialRegistry;
  CredentialRegistryIdentityValidator internal s_identityValidator;
  address internal s_owner;

  function setUp() public {
    s_owner = makeAddr("owner");

    vm.startPrank(s_owner);

    s_credentials_kyc = new bytes32[](1);
    s_credentials_kyc[0] = CREDENTIAL_KYC;

    s_credentials_accredited = new bytes32[](1);
    s_credentials_accredited[0] = CREDENTIAL_ACCREDITED;

    s_credentials_invalid_nationality = new bytes32[](1);
    s_credentials_invalid_nationality[0] = CREDENTIAL_INVALID_NATIONALITY;

    // Deploy PolicyEngine through proxy
    s_policyEngine = _deployPolicyEngine(true, address(this));

    // Deploy IdentityRegistry through proxy
    s_identityRegistry = _deployIdentityRegistry(address(s_policyEngine));

    // Deploy CredentialRegistry through proxy
    s_credentialRegistry = _deployCredentialRegistry(address(s_policyEngine));

    // Deploy CredentialRegistryIdentityValidator through proxy
    s_identityValidator = _deployCredentialRegistryIdentityValidator(
      new ICredentialRequirements.CredentialSourceInput[](0),
      new ICredentialRequirements.CredentialRequirementInput[](0)
    );

    s_identityValidator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(REQUIREMENT_KYC, s_credentials_kyc, 1, false)
    );
    s_identityValidator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_KYC, address(s_identityRegistry), address(s_credentialRegistry), address(0)
      )
    );
  }

  function test_validate_success() public {
    address account1 = makeAddr("account1");
    bytes32 ccid = keccak256("account1");

    s_identityRegistry.registerIdentity(ccid, account1, "");
    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYC, 0, "", "");

    assertTrue(s_identityValidator.validate(account1, ""));
  }

  function test_validate_altKyc_success() public {
    address account1 = makeAddr("account1");
    bytes32 ccid = keccak256("account1");

    bytes32 CREDENTIAL_BANK2_KYC = keccak256("com.bank2.kyc");

    // switch credentialValidator requirement to be either type of KYC
    s_credentials_kyc = new bytes32[](2);
    s_credentials_kyc[0] = CREDENTIAL_KYC;
    s_credentials_kyc[1] = CREDENTIAL_BANK2_KYC;
    s_identityValidator.removeCredentialRequirement(REQUIREMENT_KYC);
    s_identityValidator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(REQUIREMENT_KYC, s_credentials_kyc, 1, false)
    );
    // new kyc type can also be validated at the same registry
    s_identityValidator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_BANK2_KYC, address(s_identityRegistry), address(s_credentialRegistry), address(0)
      )
    );

    s_identityRegistry.registerIdentity(ccid, account1, "");
    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_BANK2_KYC, 0, "", "");

    assertTrue(s_identityValidator.validate(account1, ""));
  }

  function test_validate_futureExpires_success() public {
    address account1 = makeAddr("account1");
    bytes32 ccid = keccak256("account1");

    s_identityRegistry.registerIdentity(ccid, account1, "");
    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYC, uint40(block.timestamp + 30), "", "");

    vm.warp(block.timestamp + 10);

    assertTrue(s_identityValidator.validate(account1, ""));
  }

  function test_validate_expired_invalid() public {
    address account1 = makeAddr("account1");
    bytes32 ccid = keccak256("account1");

    s_identityRegistry.registerIdentity(ccid, account1, "");
    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYC, uint40(block.timestamp + 2), "", "");

    vm.warp(block.timestamp + 10);

    assertFalse(s_identityValidator.validate(account1, ""));
  }

  function test_validate_renew_success() public {
    address account1 = makeAddr("account1");
    bytes32 ccid = keccak256("account1");

    s_identityRegistry.registerIdentity(ccid, account1, "");
    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYC, uint40(block.timestamp + 2), "", "");

    vm.warp(block.timestamp + 10);

    assertFalse(s_identityValidator.validate(account1, ""));

    s_credentialRegistry.renewCredential(ccid, CREDENTIAL_KYC, uint40(block.timestamp + 30), "");
    vm.warp(block.timestamp + 10);

    assertTrue(s_identityValidator.validate(account1, ""));
  }

  function test_validate_unknownIdentity_invalid() public {
    address account1 = makeAddr("account1");

    assertFalse(s_identityValidator.validate(account1, ""));
  }

  function test_validate_missingCredential_invalid() public {
    address account1 = makeAddr("account1");
    bytes32 ccid = keccak256("account1");

    s_identityRegistry.registerIdentity(ccid, account1, "");

    assertFalse(s_identityValidator.validate(account1, ""));
  }

  function test_validate_multiSource_success() public {
    address account1 = makeAddr("account1");
    bytes32 ccid = keccak256("account1");

    s_identityValidator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(REQUIREMENT_ACCREDITED, s_credentials_accredited, 1, false)
    );

    IdentityRegistry identityRegistry2 = _deployIdentityRegistry(address(s_policyEngine));
    vm.label(address(identityRegistry2), "IdentityRegistry2");
    CredentialRegistry credentialRegistry2 = _deployCredentialRegistry(address(s_policyEngine));
    vm.label(address(credentialRegistry2), "CredentialRegistry2");

    s_identityValidator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_ACCREDITED, address(identityRegistry2), address(credentialRegistry2), address(0)
      )
    );

    s_identityRegistry.registerIdentity(ccid, account1, "");
    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYC, 0, "", "");

    identityRegistry2.registerIdentity(ccid, account1, "");
    credentialRegistry2.registerCredential(ccid, CREDENTIAL_ACCREDITED, 0, "", "");

    assertTrue(s_identityValidator.validate(account1, ""));
  }

  function test_validate_multiSourceMissingCredential_invalid() public {
    address account1 = makeAddr("account1");
    bytes32 ccid = keccak256("account1");

    s_identityValidator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(REQUIREMENT_ACCREDITED, s_credentials_accredited, 1, false)
    );

    IdentityRegistry identityRegistry2 = _deployIdentityRegistry(address(s_policyEngine));
    vm.label(address(identityRegistry2), "IdentityRegistry2");
    CredentialRegistry credentialRegistry2 = _deployCredentialRegistry(address(s_policyEngine));
    vm.label(address(credentialRegistry2), "CredentialRegistry2");

    s_identityValidator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_ACCREDITED, address(identityRegistry2), address(credentialRegistry2), address(0)
      )
    );

    identityRegistry2.registerIdentity(ccid, account1, "");
    credentialRegistry2.registerCredential(ccid, CREDENTIAL_ACCREDITED, 0, "", "");

    assertFalse(s_identityValidator.validate(account1, ""));
  }

  function test_validate_multiSource_multiCredential_success() public {
    address account1 = makeAddr("account1");
    bytes32 ccid = keccak256("account1");

    s_identityValidator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(REQUIREMENT_ACCREDITED, s_credentials_accredited, 2, false)
    );

    IdentityRegistry identityRegistry2 = _deployIdentityRegistry(address(s_policyEngine));
    vm.label(address(identityRegistry2), "IdentityRegistry2");
    CredentialRegistry credentialRegistry2 = _deployCredentialRegistry(address(s_policyEngine));
    vm.label(address(credentialRegistry2), "CredentialRegistry2");

    s_identityValidator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_ACCREDITED, address(s_identityRegistry), address(s_credentialRegistry), address(0)
      )
    );
    s_identityValidator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_ACCREDITED, address(identityRegistry2), address(credentialRegistry2), address(0)
      )
    );

    s_identityRegistry.registerIdentity(ccid, account1, "");
    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYC, 0, "", "");
    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_ACCREDITED, 0, "", "");

    identityRegistry2.registerIdentity(ccid, account1, "");
    credentialRegistry2.registerCredential(ccid, CREDENTIAL_ACCREDITED, 0, "", "");

    assertTrue(s_identityValidator.validate(account1, ""));
  }

  function test_validate_multiSource_multiCredentialMissing_invalid() public {
    address account1 = makeAddr("account1");
    bytes32 ccid = keccak256("account1");

    s_identityValidator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(REQUIREMENT_ACCREDITED, s_credentials_accredited, 2, false)
    );

    IdentityRegistry identityRegistry2 = _deployIdentityRegistry(address(s_policyEngine));
    vm.label(address(identityRegistry2), "IdentityRegistry2");
    CredentialRegistry credentialRegistry2 = _deployCredentialRegistry(address(s_policyEngine));
    vm.label(address(credentialRegistry2), "CredentialRegistry2");

    s_identityValidator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_ACCREDITED, address(s_identityRegistry), address(s_credentialRegistry), address(0)
      )
    );
    s_identityValidator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_ACCREDITED, address(identityRegistry2), address(credentialRegistry2), address(0)
      )
    );

    // no ACCREDITED credential in this registry
    s_identityRegistry.registerIdentity(ccid, account1, "");
    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYC, 0, "", "");

    identityRegistry2.registerIdentity(ccid, account1, "");
    credentialRegistry2.registerCredential(ccid, CREDENTIAL_ACCREDITED, 0, "", "");

    assertFalse(s_identityValidator.validate(account1, ""));
  }

  function test_credentialRole_success() public {
    bytes32 ccid = keccak256("account1");

    CredentialRegistry credentialRegistry2 = _deployCredentialRegistry(address(s_policyEngine));
    vm.label(address(credentialRegistry2), "CredentialRegistry2");

    vm.expectEmit();
    emit ICredentialRegistry.CredentialRegistered(ccid, CREDENTIAL_ACCREDITED, 0, "");

    credentialRegistry2.registerCredential(ccid, CREDENTIAL_ACCREDITED, 0, "", "");
  }

  function test_validate_credentialRequirementInvert_invalid() public {
    address account1 = makeAddr("account1");
    bytes32 ccid = keccak256("account1");

    s_identityRegistry.registerIdentity(ccid, account1, "");

    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYC, 0, "", "");
    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_INVALID_NATIONALITY, 0, "", "");

    s_identityValidator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(
        CREDENTIAL_INVALID_NATIONALITY, s_credentials_invalid_nationality, 1, true
      )
    );
    s_identityValidator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_INVALID_NATIONALITY, address(s_identityRegistry), address(s_credentialRegistry), address(0)
      )
    );

    assertFalse(s_identityValidator.validate(account1, ""));
  }

  function test_validate_credentialRequirementInvertCredentialExists_invalid() public {
    address account1 = makeAddr("account1");
    bytes32 ccid = keccak256("account1");

    bytes32 requirement = keccak256("mock requirement");
    bytes32[] memory credential_ids = new bytes32[](1);
    credential_ids[0] = keccak256("mock credential type");

    s_identityValidator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(requirement, credential_ids, 1, true)
    );
    s_identityValidator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        credential_ids[0], address(s_identityRegistry), address(s_credentialRegistry), address(0)
      )
    );

    s_identityRegistry.registerIdentity(ccid, account1, "");
    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYC, 0, "", "");
    s_credentialRegistry.registerCredential(ccid, credential_ids[0], 0, abi.encode("mock data"), "");

    // For inverted credentials: if credential exists in registry, validation fails (no data validation performed)
    assertFalse(s_identityValidator.validate(account1, ""));
  }

  function test_validate_credentialRequirementInvertNotPresent_succeeds() public {
    address account1 = makeAddr("account1");
    bytes32 ccid = keccak256("account1");

    s_identityRegistry.registerIdentity(ccid, account1, "");

    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYC, 0, "", "");

    s_identityValidator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(
        CREDENTIAL_INVALID_NATIONALITY, s_credentials_invalid_nationality, 1, true
      )
    );
    s_identityValidator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_INVALID_NATIONALITY, address(s_identityRegistry), address(s_credentialRegistry), address(0)
      )
    );

    assertTrue(s_identityValidator.validate(account1, ""));
  }

  function test_validate_invertCredentialRequirementNotPresentButOtherCredentialMissing_invalid() public {
    address account1 = makeAddr("account1");
    bytes32 ccid = keccak256("account1");

    s_identityRegistry.registerIdentity(ccid, account1, "");

    s_identityValidator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(
        CREDENTIAL_INVALID_NATIONALITY, s_credentials_invalid_nationality, 1, true
      )
    );
    s_identityValidator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_INVALID_NATIONALITY, address(s_identityRegistry), address(s_credentialRegistry), address(0)
      )
    );

    assertFalse(s_identityValidator.validate(account1, ""));
  }

  function test_addCredentialRequirement_zeroMinValidations_invalid() public {
    vm.expectRevert();
    s_identityValidator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(
        CREDENTIAL_INVALID_NATIONALITY, s_credentials_invalid_nationality, 0, false
      )
    );
  }

  function test_getCredentialRequirement_success() public {
    bytes32 CREDENTIAL_BANK2_KYC = keccak256("com.bank2.kyc");

    s_credentials_kyc = new bytes32[](2);
    s_credentials_kyc[0] = CREDENTIAL_KYC;
    s_credentials_kyc[1] = CREDENTIAL_BANK2_KYC;
    s_identityValidator.removeCredentialRequirement(REQUIREMENT_KYC);
    s_identityValidator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(REQUIREMENT_KYC, s_credentials_kyc, 1, false)
    );

    ICredentialRequirements.CredentialRequirement memory credRequirement =
      s_identityValidator.getCredentialRequirement(REQUIREMENT_KYC);
    assert(credRequirement.minValidations == 1);
    assert(credRequirement.credentialTypeIds[0] == CREDENTIAL_KYC);
    assert(credRequirement.credentialTypeIds[1] == CREDENTIAL_BANK2_KYC);
    assert(credRequirement.invert == false);
  }

  function test_getCredentialRequirement_duplicated_failure() public {
    bytes32 CREDENTIAL_BANK2_KYC = keccak256("com.bank2.kyc");

    s_credentials_kyc = new bytes32[](2);
    s_credentials_kyc[0] = CREDENTIAL_KYC;
    s_credentials_kyc[1] = CREDENTIAL_BANK2_KYC;

    vm.expectPartialRevert(ICredentialRequirements.RequirementExists.selector);
    s_identityValidator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(REQUIREMENT_KYC, s_credentials_kyc, 1, false)
    );
  }

  function test_getCredentialRequirementIds_success() public {
    bytes32 CREDENTIAL_BANK2_KYC = keccak256("com.bank2.kyc");

    s_credentials_kyc = new bytes32[](2);
    s_credentials_kyc[0] = CREDENTIAL_KYC;
    s_credentials_kyc[1] = CREDENTIAL_BANK2_KYC;
    s_identityValidator.removeCredentialRequirement(REQUIREMENT_KYC);
    s_identityValidator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(REQUIREMENT_KYC, s_credentials_kyc, 1, false)
    );

    bytes32[] memory requirementIds = s_identityValidator.getCredentialRequirementIds();
    assert(requirementIds.length == 1);
    assert(requirementIds[0] == REQUIREMENT_KYC);
  }

  function test_addCredentialSource_success() public {
    bytes32 CREDENTIAL_BANK2_KYC = keccak256("com.bank2.kyc");

    s_identityValidator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_BANK2_KYC, address(s_identityRegistry), address(s_credentialRegistry), address(0)
      )
    );

    ICredentialRequirements.CredentialSource[] memory credSourcesBeforeRemoval =
      s_identityValidator.getCredentialSources(CREDENTIAL_BANK2_KYC);
    assert(credSourcesBeforeRemoval.length == 1);

    s_identityValidator.removeCredentialSource(
      CREDENTIAL_BANK2_KYC, address(s_identityRegistry), address(s_credentialRegistry)
    );

    ICredentialRequirements.CredentialSource[] memory credSourcesAfterRemoval =
      s_identityValidator.getCredentialSources(CREDENTIAL_BANK2_KYC);
    assert(credSourcesAfterRemoval.length == 0);
  }

  function test_addCredentialSource_duplicated_failure() public {
    bytes32 CREDENTIAL_BANK2_KYC = keccak256("com.bank2.kyc");

    s_identityValidator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_BANK2_KYC, address(s_identityRegistry), address(s_credentialRegistry), address(0)
      )
    );

    vm.expectPartialRevert(ICredentialRequirements.SourceExists.selector);
    s_identityValidator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_BANK2_KYC, address(s_identityRegistry), address(s_credentialRegistry), address(0)
      )
    );
  }

  function test_removeCredentialRequirement_notFound_failure() public {
    vm.expectPartialRevert(ICredentialRequirements.RequirementNotFound.selector);
    s_identityValidator.removeCredentialRequirement(keccak256("unknown"));
  }

  function test_removeCredentialSource_notFound_failure() public {
    bytes32 CREDENTIAL_BANK2_KYC = keccak256("com.bank2.kyc");

    vm.expectPartialRevert(ICredentialRequirements.CredentialSourceNotFound.selector);
    s_identityValidator.removeCredentialSource(
      CREDENTIAL_BANK2_KYC, address(s_identityRegistry), address(s_credentialRegistry)
    );
  }

  function test_validate_credentialRegistryThrows_invalid() public {
    address account1 = makeAddr("account1");
    bytes32 ccid = keccak256("account1");

    // Create a mock credential registry that will throw on validate()
    MockCredentialRegistryReverting revertingRegistry = new MockCredentialRegistryReverting();
    revertingRegistry.setShouldRevert(true);
    revertingRegistry.setRevertMessage("Credential validation error");

    s_identityRegistry.registerIdentity(ccid, account1, "");

    // Add a new credential source using the reverting registry
    bytes32 CREDENTIAL_TEST = keccak256("test.credential");
    bytes32[] memory testCredentials = new bytes32[](1);
    testCredentials[0] = CREDENTIAL_TEST;

    s_identityValidator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(keccak256("TEST_REQ"), testCredentials, 1, false)
    );

    s_identityValidator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_TEST, address(s_identityRegistry), address(revertingRegistry), address(0)
      )
    );

    assertFalse(s_identityValidator.validate(account1, ""), "Should fail when credential registry throws");
  }

  function test_validate_credentialRegistryThrowsInverted_invalid() public {
    address account1 = makeAddr("account1");
    bytes32 ccid = keccak256("account1");

    MockCredentialRegistryReverting revertingRegistry = new MockCredentialRegistryReverting();
    revertingRegistry.setShouldRevert(true);
    revertingRegistry.setRevertMessage("Credential validation error");

    s_identityRegistry.registerIdentity(ccid, account1, "");

    bytes32 CREDENTIAL_BLACKLIST = keccak256("blacklist.credential");
    bytes32[] memory blacklistCredentials = new bytes32[](1);
    blacklistCredentials[0] = CREDENTIAL_BLACKLIST;

    s_identityValidator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(keccak256("NOT_BLACKLISTED"), blacklistCredentials, 1, true)
    );

    s_identityValidator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_BLACKLIST, address(s_identityRegistry), address(revertingRegistry), address(0)
      )
    );

    assertFalse(
      s_identityValidator.validate(account1, ""), "Should fail when credential registry throws, even with invert=true"
    );
  }
}
