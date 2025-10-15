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
import {BaseProxyTest} from "./helpers/BaseProxyTest.sol";

contract CredentialRegistryIdentityValidatorTest is BaseProxyTest {
  bytes32 public constant REQUIREMENT_KYC = keccak256("KYC");
  bytes32 public constant REQUIREMENT_ACCREDITED = keccak256("ACCREDITED");
  bytes32 public constant CREDENTIAL_KYC = keccak256("common.kyc");
  bytes32 public constant CREDENTIAL_PEP = keccak256("common.pep");
  bytes32 public constant CREDENTIAL_ACCREDITED = keccak256("common.accredited");
  bytes32 public constant CREDENTIAL_INVALID_NATIONALITY = keccak256("common.invalid.nationality");
  bytes32 public constant CREDENTIAL_BANK_1_KYC = keccak256("com.bank1.KYC");
  bytes32 public constant CREDENTIAL_BANK_2_KYC = keccak256("com.bank2.KYC");
  bytes32 public constant CREDENTIAL_BANK_1_PEP = keccak256("com.bank1.PEP");
  bytes32 public constant CREDENTIAL_BANK_2_PEP = keccak256("com.bank2.PEP");
  bytes32 public constant CREDENTIAL_SOURCE1_COUNTRY_A = keccak256("source1.residence.CountryA");
  bytes32 public constant CREDENTIAL_SOURCE2_COUNTRY_A = keccak256("source2.residence.CountryA");
  bytes32 public constant CREDENTIAL_SOURCE1_COUNTRY_B = keccak256("source1.residence.CountryB");
  bytes32 public constant CREDENTIAL_SOURCE2_COUNTRY_B = keccak256("source2.residence.CountryB");
  bytes32 public constant CREDENTIAL_SOURCE1_COUNTRY_C = keccak256("source1.residence.CountryC");
  bytes32 public constant CREDENTIAL_SOURCE2_COUNTRY_C = keccak256("source2.residence.CountryC");
  bytes32 public constant CREDENTIAL_SOURCE1_COUNTRY_D = keccak256("source1.residence.CountryD");
  bytes32 public constant CREDENTIAL_SOURCE2_COUNTRY_D = keccak256("source2.residence.CountryD");
  bytes32 public constant CREDENTIAL_COMMON_COUNTRY_E = keccak256("common.residence.CountryE");
  bytes32 public constant CREDENTIAL_COMMON_COUNTRY_F = keccak256("common.residence.CountryF");
  bytes32 public constant CREDENTIAL_COMMON_COUNTRY_G = keccak256("common.residence.CountryG");

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

    // switch credentialValidator requirement to be either type of KYC
    s_credentials_kyc = new bytes32[](2);
    s_credentials_kyc[0] = CREDENTIAL_KYC;
    s_credentials_kyc[1] = CREDENTIAL_BANK_2_KYC;
    s_identityValidator.removeCredentialRequirement(REQUIREMENT_KYC);
    s_identityValidator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(REQUIREMENT_KYC, s_credentials_kyc, 1, false)
    );
    // new kyc type can also be validated at the same registry
    s_identityValidator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_BANK_2_KYC, address(s_identityRegistry), address(s_credentialRegistry), address(0)
      )
    );

    s_identityRegistry.registerIdentity(ccid, account1, "");
    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_BANK_2_KYC, 0, "", "");

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
    s_credentials_kyc = new bytes32[](2);
    s_credentials_kyc[0] = CREDENTIAL_KYC;
    s_credentials_kyc[1] = CREDENTIAL_BANK_2_KYC;
    s_identityValidator.removeCredentialRequirement(REQUIREMENT_KYC);
    s_identityValidator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(REQUIREMENT_KYC, s_credentials_kyc, 1, false)
    );

    ICredentialRequirements.CredentialRequirement memory credRequirement =
      s_identityValidator.getCredentialRequirement(REQUIREMENT_KYC);
    assert(credRequirement.minValidations == 1);
    assert(credRequirement.credentialTypeIds[0] == CREDENTIAL_KYC);
    assert(credRequirement.credentialTypeIds[1] == CREDENTIAL_BANK_2_KYC);
    assert(credRequirement.invert == false);
  }

  function test_getCredentialRequirement_duplicated_failure() public {
    s_credentials_kyc = new bytes32[](2);
    s_credentials_kyc[0] = CREDENTIAL_KYC;
    s_credentials_kyc[1] = CREDENTIAL_BANK_2_KYC;

    vm.expectPartialRevert(ICredentialRequirements.RequirementExists.selector);
    s_identityValidator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(REQUIREMENT_KYC, s_credentials_kyc, 1, false)
    );
  }

  function test_getCredentialRequirementIds_success() public {
    s_credentials_kyc = new bytes32[](2);
    s_credentials_kyc[0] = CREDENTIAL_KYC;
    s_credentials_kyc[1] = CREDENTIAL_BANK_2_KYC;
    s_identityValidator.removeCredentialRequirement(REQUIREMENT_KYC);
    s_identityValidator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(REQUIREMENT_KYC, s_credentials_kyc, 1, false)
    );

    bytes32[] memory requirementIds = s_identityValidator.getCredentialRequirementIds();
    assert(requirementIds.length == 1);
    assert(requirementIds[0] == REQUIREMENT_KYC);
  }

  function test_addCredentialSource_success() public {
    s_identityValidator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_BANK_2_KYC, address(s_identityRegistry), address(s_credentialRegistry), address(0)
      )
    );

    ICredentialRequirements.CredentialSource[] memory credSourcesBeforeRemoval =
      s_identityValidator.getCredentialSources(CREDENTIAL_BANK_2_KYC);
    assert(credSourcesBeforeRemoval.length == 1);

    s_identityValidator.removeCredentialSource(
      CREDENTIAL_BANK_2_KYC, address(s_identityRegistry), address(s_credentialRegistry)
    );

    ICredentialRequirements.CredentialSource[] memory credSourcesAfterRemoval =
      s_identityValidator.getCredentialSources(CREDENTIAL_BANK_2_KYC);
    assert(credSourcesAfterRemoval.length == 0);
  }

  function test_addCredentialSource_duplicated_failure() public {
    s_identityValidator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_BANK_2_KYC, address(s_identityRegistry), address(s_credentialRegistry), address(0)
      )
    );

    vm.expectPartialRevert(ICredentialRequirements.SourceExists.selector);
    s_identityValidator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_BANK_2_KYC, address(s_identityRegistry), address(s_credentialRegistry), address(0)
      )
    );
  }

  function test_removeCredentialRequirement_notFound_failure() public {
    vm.expectPartialRevert(ICredentialRequirements.RequirementNotFound.selector);
    s_identityValidator.removeCredentialRequirement(keccak256("unknown"));
  }

  function test_removeCredentialSource_notFound_failure() public {
    vm.expectPartialRevert(ICredentialRequirements.CredentialSourceNotFound.selector);
    s_identityValidator.removeCredentialSource(
      CREDENTIAL_BANK_2_KYC, address(s_identityRegistry), address(s_credentialRegistry)
    );
  }

  function test_requireKYC_and_rejectPEP() public {
    CredentialRegistryIdentityValidator validator = _deployCredentialRegistryIdentityValidator(
      new ICredentialRequirements.CredentialSourceInput[](0),
      new ICredentialRequirements.CredentialRequirementInput[](0)
    );

    IdentityRegistry identityReg = _deployIdentityRegistry(address(s_policyEngine));
    CredentialRegistry credentialReg = _deployCredentialRegistry(address(s_policyEngine));

    bytes32[] memory kycCredentials = new bytes32[](1);
    kycCredentials[0] = CREDENTIAL_KYC;
    bytes32 REQUIREMENT_REQUIRE_KYC = keccak256("Require to have KYC");

    validator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_KYC, address(identityReg), address(credentialReg), address(0)
      )
    );

    validator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(REQUIREMENT_REQUIRE_KYC, kycCredentials, 1, false)
    );

    bytes32[] memory pepCredentials = new bytes32[](1);
    pepCredentials[0] = CREDENTIAL_PEP;
    bytes32 REQUIREMENT_REJECT_PEP = keccak256("Reject if PEP");

    validator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_PEP, address(identityReg), address(credentialReg), address(0)
      )
    );

    validator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(REQUIREMENT_REJECT_PEP, pepCredentials, 1, true)
    );

    address user1 = makeAddr("user1");
    address user2 = makeAddr("user2");
    address user3 = makeAddr("user3");
    bytes32 ccid1 = keccak256("user1");
    bytes32 ccid2 = keccak256("user2");
    bytes32 ccid3 = keccak256("user3");

    // User has KYC but is PEP, should fail
    identityReg.registerIdentity(ccid1, user1, "");
    credentialReg.registerCredential(ccid1, CREDENTIAL_KYC, 0, "", "");
    credentialReg.registerCredential(ccid1, CREDENTIAL_PEP, 0, "", "");
    assertFalse(validator.validate(user1, ""), "User with KYC but is PEP should fail");

    // User has KYC and is not PEP, should pass
    identityReg.registerIdentity(ccid2, user2, "");
    credentialReg.registerCredential(ccid2, CREDENTIAL_KYC, 0, "", "");
    assertTrue(validator.validate(user2, ""), "User with KYC and not PEP should pass");

    // User is not PEP but has no KYC, should fail
    identityReg.registerIdentity(ccid3, user3, "");
    assertFalse(validator.validate(user3, ""), "User without KYC should fail even if not PEP");
  }

  /// Same logical credential, multiple sources, whitelist
  /// Accept if user has KYC in any listed bank
  /// Config: One requirement. credentialTypeIds = [com.bank1.KYC, com.bank2.KYC], invert = false, minValidations = 1
  function test_sameLogicalCredential_multilpleSources_whitelist() public {
    CredentialRegistryIdentityValidator validator = _deployCredentialRegistryIdentityValidator(
      new ICredentialRequirements.CredentialSourceInput[](0),
      new ICredentialRequirements.CredentialRequirementInput[](0)
    );

    IdentityRegistry bank1IdentityRegistry = _deployIdentityRegistry(address(s_policyEngine));
    vm.label(address(bank1IdentityRegistry), "Bank1IdentityRegistry");
    CredentialRegistry bank1CredentialRegistry = _deployCredentialRegistry(address(s_policyEngine));
    vm.label(address(bank1CredentialRegistry), "Bank1CredentialRegistry");

    IdentityRegistry bank2IdentityRegistry = _deployIdentityRegistry(address(s_policyEngine));
    vm.label(address(bank2IdentityRegistry), "Bank2IdentityRegistry");
    CredentialRegistry bank2CredentialRegistry = _deployCredentialRegistry(address(s_policyEngine));
    vm.label(address(bank2CredentialRegistry), "Bank2CredentialRegistry");

    bytes32[] memory kycCredentials = new bytes32[](2);
    kycCredentials[0] = CREDENTIAL_BANK_1_KYC;
    kycCredentials[1] = CREDENTIAL_BANK_2_KYC;

    bytes32 REQUIREMENT_REQUIRE_ANY_KYC = keccak256("Require KYC from Bank 1 or Bank 2");

    validator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_BANK_1_KYC, address(bank1IdentityRegistry), address(bank1CredentialRegistry), address(0)
      )
    );
    validator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_BANK_2_KYC, address(bank2IdentityRegistry), address(bank2CredentialRegistry), address(0)
      )
    );

    validator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(REQUIREMENT_REQUIRE_ANY_KYC, kycCredentials, 1, false)
    );

    address user1 = makeAddr("user1");
    address user2 = makeAddr("user2");
    address user3 = makeAddr("user3");
    bytes32 ccid1 = keccak256("user1");
    bytes32 ccid2 = keccak256("user2");
    bytes32 ccid3 = keccak256("user3");

    //User has KYC only from 1, should pass
    bank1IdentityRegistry.registerIdentity(ccid1, user1, "");
    bank1CredentialRegistry.registerCredential(ccid1, CREDENTIAL_BANK_1_KYC, 0, "", "");
    assertTrue(validator.validate(user1, ""), "User with only Bank 1 KYC should pass");

    // User has KYC only from Bank 2, should pass
    bank2IdentityRegistry.registerIdentity(ccid2, user2, "");
    bank2CredentialRegistry.registerCredential(ccid2, CREDENTIAL_BANK_2_KYC, 0, "", "");
    assertTrue(validator.validate(user2, ""), "User with only Bank 2 KYC should pass");

    // User has KYC from both, should pass
    bank1IdentityRegistry.registerIdentity(ccid3, user3, "");
    bank1CredentialRegistry.registerCredential(ccid3, CREDENTIAL_BANK_1_KYC, 0, "", "");
    bank2IdentityRegistry.registerIdentity(ccid3, user3, "");
    bank2CredentialRegistry.registerCredential(ccid3, CREDENTIAL_BANK_2_KYC, 0, "", "");
    assertTrue(validator.validate(user3, ""), "User with both Bank 1 and Bank 2 KYC should pass");

    // User has no KYC, should fail
    address user4 = makeAddr("user4");
    assertFalse(validator.validate(user4, ""), "User with no KYC should fail");
  }

  function test_sameLogicalCredential_multilpleSources_whitelist_bothSourcesRequired() public {
    CredentialRegistryIdentityValidator validator = _deployCredentialRegistryIdentityValidator(
      new ICredentialRequirements.CredentialSourceInput[](0),
      new ICredentialRequirements.CredentialRequirementInput[](0)
    );

    IdentityRegistry bank1IdentityRegistry = _deployIdentityRegistry(address(s_policyEngine));
    vm.label(address(bank1IdentityRegistry), "Bank1IdentityRegistry");
    CredentialRegistry bank1CredentialRegistry = _deployCredentialRegistry(address(s_policyEngine));
    vm.label(address(bank1CredentialRegistry), "Bank1CredentialRegistry");

    IdentityRegistry bank2IdentityRegistry = _deployIdentityRegistry(address(s_policyEngine));
    vm.label(address(bank2IdentityRegistry), "Bank2IdentityRegistry");
    CredentialRegistry bank2CredentialRegistry = _deployCredentialRegistry(address(s_policyEngine));
    vm.label(address(bank2CredentialRegistry), "Bank2CredentialRegistry");

    bytes32[] memory kycCredentials = new bytes32[](2);
    kycCredentials[0] = CREDENTIAL_BANK_1_KYC;
    kycCredentials[1] = CREDENTIAL_BANK_2_KYC;

    bytes32 REQUIREMENT_REQUIRE_BOTH_KYCs = keccak256("Require KYC from Bank 1 and Bank 2");

    validator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_BANK_1_KYC, address(bank1IdentityRegistry), address(bank1CredentialRegistry), address(0)
      )
    );
    validator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_BANK_2_KYC, address(bank2IdentityRegistry), address(bank2CredentialRegistry), address(0)
      )
    );

    validator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(REQUIREMENT_REQUIRE_BOTH_KYCs, kycCredentials, 2, false)
    );

    address user1 = makeAddr("user1");
    address user2 = makeAddr("user2");
    bytes32 ccid1 = keccak256("user1");
    bytes32 ccid2 = keccak256("user2");

    // User has KYC only from Bank 1, should fail
    bank1IdentityRegistry.registerIdentity(ccid1, user1, "");
    bank1CredentialRegistry.registerCredential(ccid1, CREDENTIAL_BANK_1_KYC, 0, "", "");
    assertFalse(validator.validate(user1, ""), "User with only 1 source should fail when minValidations = 2");

    // User has KYC from both Bank 1 and Bank 2, should pass
    bank1IdentityRegistry.registerIdentity(ccid2, user2, "");
    bank1CredentialRegistry.registerCredential(ccid2, CREDENTIAL_BANK_1_KYC, 0, "", "");
    bank2IdentityRegistry.registerIdentity(ccid2, user2, "");
    bank2CredentialRegistry.registerCredential(ccid2, CREDENTIAL_BANK_2_KYC, 0, "", "");
    assertTrue(validator.validate(user2, ""), "User with 2 sources should pass when minValidations = 2");
  }

  /// Denylist across multiple sources
  /// Reject if user is PEP in any source
  /// Config: One requirement. credentialTypeIds = [bank1.PEP, bank2.PEP], invert = true, minValidations = 2
  function test_denylistWithMultipleSources_mustBeCleanInAllSources() public {
    CredentialRegistryIdentityValidator validator = _deployCredentialRegistryIdentityValidator(
      new ICredentialRequirements.CredentialSourceInput[](0),
      new ICredentialRequirements.CredentialRequirementInput[](0)
    );

    IdentityRegistry bank1IdentityRegistry = _deployIdentityRegistry(address(s_policyEngine));
    vm.label(address(bank1IdentityRegistry), "Bank1IdentityRegistry");
    CredentialRegistry bank1CredentialRegistry = _deployCredentialRegistry(address(s_policyEngine));
    vm.label(address(bank1CredentialRegistry), "Bank1CredentialRegistry");

    IdentityRegistry bank2IdentityRegistry = _deployIdentityRegistry(address(s_policyEngine));
    vm.label(address(bank2IdentityRegistry), "Bank2IdentityRegistry");
    CredentialRegistry bank2CredentialRegistry = _deployCredentialRegistry(address(s_policyEngine));
    vm.label(address(bank2CredentialRegistry), "Bank2CredentialRegistry");

    bytes32[] memory pepCredentials = new bytes32[](2);
    pepCredentials[0] = CREDENTIAL_BANK_1_PEP;
    pepCredentials[1] = CREDENTIAL_BANK_2_PEP;

    bytes32 REQUIREMENT_NOT_PEP = keccak256("Require not to have PEP");

    validator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_BANK_1_PEP, address(bank1IdentityRegistry), address(bank1CredentialRegistry), address(0)
      )
    );
    validator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_BANK_2_PEP, address(bank2IdentityRegistry), address(bank2CredentialRegistry), address(0)
      )
    );

    validator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(REQUIREMENT_NOT_PEP, pepCredentials, 2, true)
    );

    address user1 = makeAddr("user1");
    address user2 = makeAddr("user2");
    address user3 = makeAddr("user3");
    address user4 = makeAddr("user4");
    bytes32 ccid1 = keccak256("user1");
    bytes32 ccid2 = keccak256("user2");
    bytes32 ccid3 = keccak256("user3");
    bytes32 ccid4 = keccak256("user4");

    // User is PEP in Bank 1, should fail
    bank1IdentityRegistry.registerIdentity(ccid1, user1, "");
    bank1CredentialRegistry.registerCredential(ccid1, CREDENTIAL_BANK_1_PEP, 0, "", "");
    bank2IdentityRegistry.registerIdentity(ccid1, user1, "");
    assertFalse(validator.validate(user1, ""), "User who is PEP in Bank 1 should fail");

    // User is PEP in Bank 2, should fail
    bank1IdentityRegistry.registerIdentity(ccid2, user2, "");
    bank2IdentityRegistry.registerIdentity(ccid2, user2, "");
    bank2CredentialRegistry.registerCredential(ccid2, CREDENTIAL_BANK_2_PEP, 0, "", "");
    assertFalse(validator.validate(user2, ""), "User who is PEP in Bank 2 should fail");

    // User is PEP in both, should fail
    bank1IdentityRegistry.registerIdentity(ccid3, user3, "");
    bank1CredentialRegistry.registerCredential(ccid3, CREDENTIAL_BANK_1_PEP, 0, "", "");
    bank2IdentityRegistry.registerIdentity(ccid3, user3, "");
    bank2CredentialRegistry.registerCredential(ccid3, CREDENTIAL_BANK_2_PEP, 0, "", "");
    assertFalse(validator.validate(user3, ""), "User who is PEP in both should fail");

    // User is not PEP in either source, should pass
    bank1IdentityRegistry.registerIdentity(ccid4, user4, "");
    bank2IdentityRegistry.registerIdentity(ccid4, user4, "");
    assertTrue(validator.validate(user4, ""), "User who is not PEP in any source should pass");
  }

  /// Jurisdiction whitelist
  /// User must belong to any allowed residence
  /// Config: One requirement. credentialTypeIds = [common.residence.CountryE, common.residence.CountryF,
  /// common.residence.CountryG], invert = false, minValidations = 1
  function test_jurisdictionWhitelist_ifOneCredentialIsPresentItMustSucceed() public {
    CredentialRegistryIdentityValidator validator = _deployCredentialRegistryIdentityValidator(
      new ICredentialRequirements.CredentialSourceInput[](0),
      new ICredentialRequirements.CredentialRequirementInput[](0)
    );

    IdentityRegistry identityReg = _deployIdentityRegistry(address(s_policyEngine));
    CredentialRegistry credentialReg = _deployCredentialRegistry(address(s_policyEngine));

    bytes32[] memory jurisdictionCredentials = new bytes32[](3);
    jurisdictionCredentials[0] = CREDENTIAL_COMMON_COUNTRY_E;
    jurisdictionCredentials[1] = CREDENTIAL_COMMON_COUNTRY_F;
    jurisdictionCredentials[2] = CREDENTIAL_COMMON_COUNTRY_G;

    bytes32 REQUIREMENT_REQUIRE_ANY_JURISDICTION = keccak256("Require any of the allowed jurisdictions");

    validator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_COMMON_COUNTRY_E, address(identityReg), address(credentialReg), address(0)
      )
    );
    validator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_COMMON_COUNTRY_F, address(identityReg), address(credentialReg), address(0)
      )
    );
    validator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_COMMON_COUNTRY_G, address(identityReg), address(credentialReg), address(0)
      )
    );

    validator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(
        REQUIREMENT_REQUIRE_ANY_JURISDICTION, jurisdictionCredentials, 1, false
      )
    );

    address user1 = makeAddr("user1");
    address user2 = makeAddr("user2");
    address user3 = makeAddr("user3");
    bytes32 ccid1 = keccak256("user1");
    bytes32 ccid2 = keccak256("user2");
    bytes32 ccid3 = keccak256("user3");

    // User is CountryE resident, should pass
    identityReg.registerIdentity(ccid1, user1, "");
    credentialReg.registerCredential(ccid1, CREDENTIAL_COMMON_COUNTRY_E, 0, "", "");
    assertTrue(validator.validate(user1, ""), "CountryE resident should pass");

    // User is CountryF resident, should pass
    identityReg.registerIdentity(ccid2, user2, "");
    credentialReg.registerCredential(ccid2, CREDENTIAL_COMMON_COUNTRY_F, 0, "", "");
    assertTrue(validator.validate(user2, ""), "CountryF resident should pass");

    // User is CountryG resident, should pass
    identityReg.registerIdentity(ccid3, user3, "");
    credentialReg.registerCredential(ccid3, CREDENTIAL_COMMON_COUNTRY_G, 0, "", "");
    assertTrue(validator.validate(user3, ""), "CountryG resident should pass");
  }

  /// Jurisdiction denylist
  /// User must not be in any of the banned jurisdictions
  /// Config: One requirement per jurisdiction, each with its own sources
  /// For CountryA: credentialTypeIds = [source1.CountryA, source2.CountryA], invert = true, minValidations = 2
  /// And so on for each banned jurisdiction...
  function test_jurisdictionDenylist_mustNotBeInAnyOfTheBannedJurisdictions() public {
    CredentialRegistryIdentityValidator validator = _deployCredentialRegistryIdentityValidator(
      new ICredentialRequirements.CredentialSourceInput[](0),
      new ICredentialRequirements.CredentialRequirementInput[](0)
    );

    IdentityRegistry source1IdentityReg = _deployIdentityRegistry(address(s_policyEngine));
    vm.label(address(source1IdentityReg), "Source1IdentityRegistry");
    CredentialRegistry source1CredentialReg = _deployCredentialRegistry(address(s_policyEngine));
    vm.label(address(source1CredentialReg), "Source1CredentialRegistry");

    IdentityRegistry source2IdentityReg = _deployIdentityRegistry(address(s_policyEngine));
    vm.label(address(source2IdentityReg), "Source2IdentityRegistry");
    CredentialRegistry source2CredentialReg = _deployCredentialRegistry(address(s_policyEngine));
    vm.label(address(source2CredentialReg), "Source2CredentialRegistry");

    bytes32[] memory countryACredentials = new bytes32[](2);
    countryACredentials[0] = CREDENTIAL_SOURCE1_COUNTRY_A;
    countryACredentials[1] = CREDENTIAL_SOURCE2_COUNTRY_A;

    bytes32 REQUIREMENT_NOT_COUNTRY_A = keccak256("Require not to be CountryA resident");

    validator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_SOURCE1_COUNTRY_A, address(source1IdentityReg), address(source1CredentialReg), address(0)
      )
    );
    validator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_SOURCE2_COUNTRY_A, address(source2IdentityReg), address(source2CredentialReg), address(0)
      )
    );

    validator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(REQUIREMENT_NOT_COUNTRY_A, countryACredentials, 2, true)
    );

    bytes32[] memory countryBCredentials = new bytes32[](2);
    countryBCredentials[0] = CREDENTIAL_SOURCE1_COUNTRY_B;
    countryBCredentials[1] = CREDENTIAL_SOURCE2_COUNTRY_B;

    bytes32 REQUIREMENT_NOT_COUNTRY_B = keccak256("Require not to be CountryB resident");

    validator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_SOURCE1_COUNTRY_B, address(source1IdentityReg), address(source1CredentialReg), address(0)
      )
    );
    validator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_SOURCE2_COUNTRY_B, address(source2IdentityReg), address(source2CredentialReg), address(0)
      )
    );

    validator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(REQUIREMENT_NOT_COUNTRY_B, countryBCredentials, 2, true)
    );

    bytes32[] memory countryCCredentials = new bytes32[](2);
    countryCCredentials[0] = CREDENTIAL_SOURCE1_COUNTRY_C;
    countryCCredentials[1] = CREDENTIAL_SOURCE2_COUNTRY_C;

    bytes32 REQUIREMENT_NOT_COUNTRY_C = keccak256("Require not to be CountryC resident");

    validator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_SOURCE1_COUNTRY_C, address(source1IdentityReg), address(source1CredentialReg), address(0)
      )
    );

    validator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_SOURCE2_COUNTRY_C, address(source2IdentityReg), address(source2CredentialReg), address(0)
      )
    );

    validator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(REQUIREMENT_NOT_COUNTRY_C, countryCCredentials, 2, true)
    );

    bytes32[] memory countryDCredentials = new bytes32[](2);
    countryDCredentials[0] = CREDENTIAL_SOURCE1_COUNTRY_D;
    countryDCredentials[1] = CREDENTIAL_SOURCE2_COUNTRY_D;

    bytes32 REQUIREMENT_NOT_COUNTRY_D = keccak256("Require not to be CountryD resident");

    validator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_SOURCE1_COUNTRY_D, address(source1IdentityReg), address(source1CredentialReg), address(0)
      )
    );

    validator.addCredentialSource(
      ICredentialRequirements.CredentialSourceInput(
        CREDENTIAL_SOURCE2_COUNTRY_D, address(source2IdentityReg), address(source2CredentialReg), address(0)
      )
    );

    validator.addCredentialRequirement(
      ICredentialRequirements.CredentialRequirementInput(REQUIREMENT_NOT_COUNTRY_D, countryDCredentials, 2, true)
    );

    address user1 = makeAddr("user1");
    address user2 = makeAddr("user2");
    address user3 = makeAddr("user3");
    address user4 = makeAddr("user4");
    address user5 = makeAddr("user5");
    bytes32 ccid1 = keccak256("user1");
    bytes32 ccid2 = keccak256("user2");
    bytes32 ccid3 = keccak256("user3");
    bytes32 ccid4 = keccak256("user4");
    bytes32 ccid5 = keccak256("user5");

    // User is CountryA resident in source1, should fail
    source1IdentityReg.registerIdentity(ccid1, user1, "");
    source1CredentialReg.registerCredential(ccid1, CREDENTIAL_SOURCE1_COUNTRY_A, 0, "", "");
    source2IdentityReg.registerIdentity(ccid1, user1, "");
    assertFalse(validator.validate(user1, ""), "CountryA resident should fail");

    // User is CountryB resident in source2, should fail
    source1IdentityReg.registerIdentity(ccid2, user2, "");
    source2IdentityReg.registerIdentity(ccid2, user2, "");
    source2CredentialReg.registerCredential(ccid2, CREDENTIAL_SOURCE2_COUNTRY_B, 0, "", "");
    assertFalse(validator.validate(user2, ""), "CountryB resident should fail");

    // User is CountryC resident in both sources, should fail
    source1IdentityReg.registerIdentity(ccid3, user3, "");
    source1CredentialReg.registerCredential(ccid3, CREDENTIAL_SOURCE1_COUNTRY_C, 0, "", "");
    source2IdentityReg.registerIdentity(ccid3, user3, "");
    source2CredentialReg.registerCredential(ccid3, CREDENTIAL_SOURCE2_COUNTRY_C, 0, "", "");
    assertFalse(validator.validate(user3, ""), "CountryC resident should fail");

    // User is CountryD resident in source1, should fail
    source1IdentityReg.registerIdentity(ccid4, user4, "");
    source1CredentialReg.registerCredential(ccid4, CREDENTIAL_SOURCE1_COUNTRY_D, 0, "", "");
    source2IdentityReg.registerIdentity(ccid4, user4, "");
    assertFalse(validator.validate(user4, ""), "CountryD resident should fail");

    // User is not in banned jurisdictions, should PASS
    source1IdentityReg.registerIdentity(ccid5, user5, "");
    source2IdentityReg.registerIdentity(ccid5, user5, "");
    assertTrue(validator.validate(user5, ""), "Clean user should pass");
  }
}
