// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {ICredentialRequirements} from "../src/interfaces/ICredentialRequirements.sol";
import {IGroupedCredentialRequirements} from "../src/interfaces/IGroupedCredentialRequirements.sol";
import {IIdentityValidator} from "../src/interfaces/IIdentityValidator.sol";
import {GroupedIdentityValidatorPolicy} from "../src/GroupedIdentityValidatorPolicy.sol";
import {IdentityRegistry} from "../src/IdentityRegistry.sol";
import {CredentialRegistry} from "../src/CredentialRegistry.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {Policy} from "@chainlink/policy-management/core/Policy.sol";
import {PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {BaseProxyTest} from "./helpers/BaseProxyTest.sol";

contract GroupedIdentityValidatorPolicyTest is BaseProxyTest {
  bytes32 public constant GROUP_PERSON = keccak256("PERSON");
  bytes32 public constant GROUP_BUSINESS = keccak256("BUSINESS");
  bytes32 public constant REQUIREMENT_KYC = keccak256("KYC");
  bytes32 public constant REQUIREMENT_COUNTRY = keccak256("COUNTRY");
  bytes32 public constant CREDENTIAL_KYC = keccak256("common.kyc");
  bytes32 public constant CREDENTIAL_KYB = keccak256("common.kyb");
  bytes32 public constant CREDENTIAL_COUNTRY = keccak256("common.country");

  PolicyEngine internal s_policyEngine;
  IdentityRegistry internal s_identityRegistry;
  CredentialRegistry internal s_credentialRegistry;
  GroupedIdentityValidatorPolicy internal s_policy;
  address internal s_owner;

  function setUp() public {
    s_owner = makeAddr("owner");
    s_policyEngine = _deployPolicyEngine(true, address(this));
    s_identityRegistry = _deployIdentityRegistry(address(s_policyEngine));
    s_credentialRegistry = _deployCredentialRegistry(address(s_policyEngine));
    s_policy = _deployGroupedPolicy("");
  }

  function test_addGroup_routingAloneValidation_success() public {
    _addAttestationGroup(GROUP_PERSON, CREDENTIAL_KYC, false);

    address account = makeAddr("account");
    bytes32 ccid = keccak256("account");
    s_identityRegistry.registerIdentity(ccid, account, "");
    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYC, 0, "", "");

    assertTrue(s_policy.validate(account, ""));

    bytes[] memory parameters = new bytes[](1);
    parameters[0] = abi.encode(account);
    assertEq(
      uint256(s_policy.run(address(0), address(0), 0x00000000, parameters, "")),
      uint256(IPolicyEngine.PolicyResult.Continue)
    );
  }

  function test_addGroup_revertsOnRoutingOverlap() public {
    _addAttestationGroup(GROUP_PERSON, CREDENTIAL_KYC, false);

    vm.expectPartialRevert(IGroupedCredentialRequirements.RoutingOverlap.selector);
    s_policy.addGroup(
      IGroupedCredentialRequirements.GroupInput(
        GROUP_BUSINESS,
        _singletonType(CREDENTIAL_KYC),
        IGroupedCredentialRequirements.RoutingKind.Attestation,
        new bytes32[](0),
        1
      )
    );
  }

  function test_addGroup_revertsWhenRoutingMinValidationsZero() public {
    vm.expectRevert(
      abi.encodeWithSelector(
        IGroupedCredentialRequirements.InvalidGroupConfiguration.selector,
        "routing minValidations must be greater than 0"
      )
    );
    s_policy.addGroup(
      IGroupedCredentialRequirements.GroupInput(
        GROUP_BUSINESS,
        _singletonType(CREDENTIAL_KYB),
        IGroupedCredentialRequirements.RoutingKind.Attestation,
        new bytes32[](0),
        0
      )
    );
  }

  function test_run_firstGroupWinsWhenMultipleGroupsMatch() public {
    _addAttestationGroup(GROUP_PERSON, CREDENTIAL_KYC, false);
    _addAttestationGroup(GROUP_BUSINESS, CREDENTIAL_KYB, false);

    address account = makeAddr("account");
    bytes32 ccid = keccak256("account");
    s_identityRegistry.registerIdentity(ccid, account, "");
    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYC, 0, "", "");
    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYB, 0, "", "");

    bytes[] memory parameters = new bytes[](1);
    parameters[0] = abi.encode(account);

    // GROUP_PERSON was added first, so it should match even though GROUP_BUSINESS also matches
    assertEq(
      uint256(s_policy.run(address(0), address(0), 0x00000000, parameters, "")),
      uint256(IPolicyEngine.PolicyResult.Continue)
    );
    assertTrue(s_policy.validate(account, ""));
  }

  function test_run_firstGroupWinsWhenSecondGroupWouldFailRequirements() public {
    // Group 1 routes on cred A (KYC) and has no requirements, so it always passes once routed.
    _addAttestationGroup(GROUP_PERSON, CREDENTIAL_KYC, false);

    // Group 2 routes on cred B (KYB) but requires cred C (COUNTRY). Account won't have cred C.
    _addAttestationGroup(GROUP_BUSINESS, CREDENTIAL_KYB, false);
    s_policy.addGroupRequirement(GROUP_BUSINESS, REQUIREMENT_COUNTRY, _singletonType(CREDENTIAL_COUNTRY), 1, false);

    address account = makeAddr("account");
    bytes32 ccid = keccak256("account");
    s_identityRegistry.registerIdentity(ccid, account, "");
    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYC, 0, "", "");
    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYB, 0, "", "");

    // If routed to GROUP_BUSINESS, this would fail (missing CREDENTIAL_COUNTRY).
    // Since GROUP_PERSON was added first and also matches, first-match routing must route to GROUP_PERSON and pass.
    bytes[] memory parameters = new bytes[](1);
    parameters[0] = abi.encode(account);
    assertEq(
      uint256(s_policy.run(address(0), address(0), 0x00000000, parameters, "")),
      uint256(IPolicyEngine.PolicyResult.Continue)
    );
    assertTrue(s_policy.validate(account, ""));

    // Control: if the "stricter" group is added first, routing will pick it and the policy should reject.
    GroupedIdentityValidatorPolicy strictFirst = _deployGroupedPolicy("");
    strictFirst.addGroup(
      IGroupedCredentialRequirements.GroupInput(
        GROUP_BUSINESS,
        _singletonType(CREDENTIAL_KYB),
        IGroupedCredentialRequirements.RoutingKind.Attestation,
        new bytes32[](0),
        1
      )
    );
    strictFirst.addGroupSource(
      GROUP_BUSINESS, CREDENTIAL_KYB, address(s_identityRegistry), address(s_credentialRegistry), address(0)
    );
    strictFirst.addGroupRequirement(GROUP_BUSINESS, REQUIREMENT_COUNTRY, _singletonType(CREDENTIAL_COUNTRY), 1, false);

    strictFirst.addGroup(
      IGroupedCredentialRequirements.GroupInput(
        GROUP_PERSON,
        _singletonType(CREDENTIAL_KYC),
        IGroupedCredentialRequirements.RoutingKind.Attestation,
        new bytes32[](0),
        1
      )
    );
    strictFirst.addGroupSource(
      GROUP_PERSON, CREDENTIAL_KYC, address(s_identityRegistry), address(s_credentialRegistry), address(0)
    );

    vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.PolicyRejected.selector, "group requirements failed"));
    strictFirst.run(address(0), address(0), 0x00000000, parameters, "");
    assertFalse(strictFirst.validate(account, ""));
  }

  function test_dataRouting_matchesAcceptableData() public {
    bytes memory us = abi.encode("US");
    bytes memory ca = abi.encode("CA");
    _addDataRoutingGroup(GROUP_PERSON, CREDENTIAL_COUNTRY, us);

    address account = makeAddr("account");
    bytes32 ccid = keccak256("account");
    s_identityRegistry.registerIdentity(ccid, account, "");
    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_COUNTRY, 0, us, "");
    assertTrue(s_policy.validate(account, ""));

    address account2 = makeAddr("account2");
    bytes32 ccid2 = keccak256("account2");
    s_identityRegistry.registerIdentity(ccid2, account2, "");
    s_credentialRegistry.registerCredential(ccid2, CREDENTIAL_COUNTRY, 0, ca, "");
    assertFalse(s_policy.validate(account2, ""));
  }

  function test_policy_supportsAttestationAndDataRoutingGroups() public {
    bytes memory us = abi.encode("US");

    // Group 1: attestation routing.
    _addAttestationGroup(GROUP_PERSON, CREDENTIAL_KYC, false);

    // Group 2: data routing.
    _addDataRoutingGroup(GROUP_BUSINESS, CREDENTIAL_COUNTRY, us);

    // Sanity: both routing kinds are stored as configured.
    assertEq(
      uint8(s_policy.getGroupRouting(GROUP_PERSON).kind), uint8(IGroupedCredentialRequirements.RoutingKind.Attestation)
    );
    assertEq(
      uint8(s_policy.getGroupRouting(GROUP_BUSINESS).kind), uint8(IGroupedCredentialRequirements.RoutingKind.Data)
    );

    // Account with only KYC routes to GROUP_PERSON and passes.
    address kycOnly = makeAddr("kycOnly");
    bytes32 kycOnlyCcid = keccak256("kycOnly");
    s_identityRegistry.registerIdentity(kycOnlyCcid, kycOnly, "");
    s_credentialRegistry.registerCredential(kycOnlyCcid, CREDENTIAL_KYC, 0, "", "");
    assertTrue(s_policy.validate(kycOnly, ""));

    // Account with only COUNTRY=US routes to GROUP_BUSINESS and passes.
    address usOnly = makeAddr("usOnly");
    bytes32 usOnlyCcid = keccak256("usOnly");
    s_identityRegistry.registerIdentity(usOnlyCcid, usOnly, "");
    s_credentialRegistry.registerCredential(usOnlyCcid, CREDENTIAL_COUNTRY, 0, us, "");
    assertTrue(s_policy.validate(usOnly, ""));
  }

  function test_routing_minValidations_requiresMultipleSourceMatches() public {
    IdentityRegistry identityB = _deployIdentityRegistry(address(s_policyEngine));
    CredentialRegistry credentialB = _deployCredentialRegistry(address(s_policyEngine));

    // Same credential type, two independent sources (dual attestation–style routing).
    s_policy.addGroup(
      IGroupedCredentialRequirements.GroupInput(
        GROUP_PERSON,
        _singletonType(CREDENTIAL_KYC),
        IGroupedCredentialRequirements.RoutingKind.Attestation,
        new bytes32[](0),
        2
      )
    );
    s_policy.addGroupSource(
      GROUP_PERSON, CREDENTIAL_KYC, address(s_identityRegistry), address(s_credentialRegistry), address(0)
    );
    s_policy.addGroupSource(GROUP_PERSON, CREDENTIAL_KYC, address(identityB), address(credentialB), address(0));

    address partialAccount = makeAddr("partial");
    bytes32 partialCcid = keccak256("partial");
    s_identityRegistry.registerIdentity(partialCcid, partialAccount, "");
    s_credentialRegistry.registerCredential(partialCcid, CREDENTIAL_KYC, 0, "", "");

    assertFalse(s_policy.validate(partialAccount, ""));
    bytes[] memory parameters = new bytes[](1);
    parameters[0] = abi.encode(partialAccount);
    vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.PolicyRejected.selector, "no routing match"));
    s_policy.run(address(0), address(0), 0x00000000, parameters, "");

    address full = makeAddr("full");
    bytes32 fullCcid = keccak256("full");
    s_identityRegistry.registerIdentity(fullCcid, full, "");
    s_credentialRegistry.registerCredential(fullCcid, CREDENTIAL_KYC, 0, "", "");
    identityB.registerIdentity(fullCcid, full, "");
    credentialB.registerCredential(fullCcid, CREDENTIAL_KYC, 0, "", "");

    assertTrue(s_policy.validate(full, ""));
    parameters[0] = abi.encode(full);
    assertEq(
      uint256(s_policy.run(address(0), address(0), 0x00000000, parameters, "")),
      uint256(IPolicyEngine.PolicyResult.Continue)
    );
  }

  function test_updateGroupRouting_raisingMinValidations_failsRoutingUntilSourceAdded() public {
    _addAttestationGroup(GROUP_PERSON, CREDENTIAL_KYC, false, 1);

    address account = makeAddr("account");
    bytes32 ccid = keccak256("account");
    s_identityRegistry.registerIdentity(ccid, account, "");
    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYC, 0, "", "");
    assertTrue(s_policy.validate(account, ""));

    // Raise threshold to 2 — only 1 source exists, routing should no longer match.
    s_policy.updateGroupRouting(
      GROUP_PERSON,
      IGroupedCredentialRequirements.RoutingConfig({
        credentialTypeIds: _singletonType(CREDENTIAL_KYC),
        kind: IGroupedCredentialRequirements.RoutingKind.Attestation,
        criteria: new bytes32[](0),
        minValidations: 2
      })
    );
    assertFalse(s_policy.validate(account, ""));

    bytes[] memory parameters = new bytes[](1);
    parameters[0] = abi.encode(account);
    vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.PolicyRejected.selector, "no routing match"));
    s_policy.run(address(0), address(0), 0x00000000, parameters, "");

    // Adding a second source satisfies the updated threshold.
    IdentityRegistry identityB = _deployIdentityRegistry(address(s_policyEngine));
    CredentialRegistry credentialB = _deployCredentialRegistry(address(s_policyEngine));
    s_policy.addGroupSource(GROUP_PERSON, CREDENTIAL_KYC, address(identityB), address(credentialB), address(0));
    identityB.registerIdentity(ccid, account, "");
    credentialB.registerCredential(ccid, CREDENTIAL_KYC, 0, "", "");
    assertTrue(s_policy.validate(account, ""));
  }

  function test_routing_minValidations_exactlyAtThreshold_passes() public {
    IdentityRegistry identityB = _deployIdentityRegistry(address(s_policyEngine));
    CredentialRegistry credentialB = _deployCredentialRegistry(address(s_policyEngine));

    // Two sources, threshold exactly 2.
    _addAttestationGroup(GROUP_PERSON, CREDENTIAL_KYC, false, 2);
    s_policy.addGroupSource(GROUP_PERSON, CREDENTIAL_KYC, address(identityB), address(credentialB), address(0));

    address account = makeAddr("account");
    bytes32 ccid = keccak256("account");
    s_identityRegistry.registerIdentity(ccid, account, "");
    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYC, 0, "", "");
    identityB.registerIdentity(ccid, account, "");
    credentialB.registerCredential(ccid, CREDENTIAL_KYC, 0, "", "");

    // Exactly 2 matching sources with minValidations=2 — should pass.
    assertTrue(s_policy.validate(account, ""));
    bytes[] memory parameters = new bytes[](1);
    parameters[0] = abi.encode(account);
    assertEq(
      uint256(s_policy.run(address(0), address(0), 0x00000000, parameters, "")),
      uint256(IPolicyEngine.PolicyResult.Continue)
    );
  }

  function test_postRun_emitsRoutingAndRequirementEvents() public {
    _addAttestationGroup(GROUP_PERSON, CREDENTIAL_KYC, true);

    address account = makeAddr("account");
    bytes32 ccid = keccak256("account");
    s_identityRegistry.registerIdentity(ccid, account, "");
    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYC, 0, "", "");

    bytes[] memory parameters = new bytes[](1);
    parameters[0] = abi.encode(account);

    vm.expectEmit(true, true, true, true, address(s_policy));
    emit IIdentityValidator.IdentityValidated(
      account, ccid, CREDENTIAL_KYC, address(s_credentialRegistry), address(0), bytes32(0)
    );
    vm.expectEmit(true, true, true, true, address(s_policy));
    emit IIdentityValidator.IdentityValidated(
      account, ccid, CREDENTIAL_KYC, address(s_credentialRegistry), address(0), bytes32(0)
    );

    vm.prank(address(s_policyEngine));
    s_policy.postRun(address(0), address(0), 0x00000000, parameters, "");
  }

  // authorizeConfigSelector

  function test_authorizeConfigSelector_returnsTrueForAllMutatingSelectors() public view {
    assertTrue(s_policy.authorizeConfigSelector(s_policy.addGroup.selector));
    assertTrue(s_policy.authorizeConfigSelector(s_policy.removeGroup.selector));
    assertTrue(s_policy.authorizeConfigSelector(s_policy.updateGroupRouting.selector));
    assertTrue(s_policy.authorizeConfigSelector(s_policy.addGroupRequirement.selector));
    assertTrue(s_policy.authorizeConfigSelector(s_policy.removeGroupRequirement.selector));
    assertTrue(s_policy.authorizeConfigSelector(s_policy.addGroupSource.selector));
    assertTrue(s_policy.authorizeConfigSelector(s_policy.removeGroupSource.selector));
  }

  function test_authorizeConfigSelector_returnsFalseForUnauthorizedSelector() public view {
    assertFalse(s_policy.authorizeConfigSelector(s_policy.run.selector));
  }

  function test_setPolicyConfiguration_authorizedSelector_callsFunction() public {
    GroupedIdentityValidatorPolicy policy = _deployGroupedPolicyOwnedByEngine();

    IGroupedCredentialRequirements.GroupInput memory input = IGroupedCredentialRequirements.GroupInput({
      groupId: GROUP_PERSON,
      routingCredentialTypeIds: _singletonType(CREDENTIAL_KYC),
      routingKind: IGroupedCredentialRequirements.RoutingKind.Attestation,
      routingCriteria: new bytes32[](0),
      routingMinValidations: 1
    });

    s_policyEngine.setPolicyConfiguration(address(policy), 0, s_policy.addGroup.selector, abi.encode(input));

    bytes32[] memory groupIds = policy.getGroupIds();
    assertEq(groupIds.length, 1);
    assertEq(groupIds[0], GROUP_PERSON);
  }

  function test_setPolicyConfiguration_unauthorizedSelector_reverts() public {
    vm.expectPartialRevert(IPolicyEngine.PolicyConfigurationError.selector);
    s_policyEngine.setPolicyConfiguration(address(s_policy), 0, s_policy.run.selector, "");
  }

  function test_removeGroup_clearsStoredSources() public {
    _addAttestationGroup(GROUP_PERSON, CREDENTIAL_KYC, false);
    assertEq(s_policy.getGroupSources(GROUP_PERSON, CREDENTIAL_KYC).length, 1);

    s_policy.removeGroup(GROUP_PERSON);

    // Re-add the same group id; the previously stored sources must not survive the removal.
    s_policy.addGroup(
      IGroupedCredentialRequirements.GroupInput(
        GROUP_PERSON,
        _singletonType(CREDENTIAL_KYC),
        IGroupedCredentialRequirements.RoutingKind.Attestation,
        new bytes32[](0),
        1
      )
    );
    assertEq(s_policy.getGroupSources(GROUP_PERSON, CREDENTIAL_KYC).length, 0);
  }

  function test_removeGroupSource_multipleTypes_untracksWithoutCorruptingOthers() public {
    // Track three distinct credential types, then remove a non-last one to exercise the swap-and-pop path,
    // followed by removing the entry that was swapped into its place.
    _addAttestationGroup(GROUP_PERSON, CREDENTIAL_KYC, false);
    s_policy.addGroupSource(
      GROUP_PERSON, CREDENTIAL_KYB, address(s_identityRegistry), address(s_credentialRegistry), address(0)
    );
    s_policy.addGroupSource(
      GROUP_PERSON, CREDENTIAL_COUNTRY, address(s_identityRegistry), address(s_credentialRegistry), address(0)
    );

    // Remove the first-tracked type (KYC); COUNTRY (the last entry) gets swapped into its slot.
    s_policy.removeGroupSource(GROUP_PERSON, CREDENTIAL_KYC, address(s_identityRegistry), address(s_credentialRegistry));
    assertEq(s_policy.getGroupSources(GROUP_PERSON, CREDENTIAL_KYC).length, 0);
    assertEq(s_policy.getGroupSources(GROUP_PERSON, CREDENTIAL_KYB).length, 1);
    assertEq(s_policy.getGroupSources(GROUP_PERSON, CREDENTIAL_COUNTRY).length, 1);

    // Remove the swapped-in entry (COUNTRY) to confirm its tracking index was updated correctly.
    s_policy.removeGroupSource(
      GROUP_PERSON, CREDENTIAL_COUNTRY, address(s_identityRegistry), address(s_credentialRegistry)
    );
    assertEq(s_policy.getGroupSources(GROUP_PERSON, CREDENTIAL_COUNTRY).length, 0);
    assertEq(s_policy.getGroupSources(GROUP_PERSON, CREDENTIAL_KYB).length, 1);

    // Removing the group must clear the only remaining tracked type and leave no stale state on re-add.
    s_policy.removeGroup(GROUP_PERSON);
    s_policy.addGroup(
      IGroupedCredentialRequirements.GroupInput(
        GROUP_PERSON,
        _singletonType(CREDENTIAL_KYC),
        IGroupedCredentialRequirements.RoutingKind.Attestation,
        new bytes32[](0),
        1
      )
    );
    assertEq(s_policy.getGroupSources(GROUP_PERSON, CREDENTIAL_KYB).length, 0);
  }

  function test_removeGroupSource_thenRemoveGroup_leavesNoStaleSources() public {
    // Add a source, remove it (untracking the type), add another, then remove and re-add the group.
    _addAttestationGroup(GROUP_PERSON, CREDENTIAL_KYC, false);
    s_policy.removeGroupSource(GROUP_PERSON, CREDENTIAL_KYC, address(s_identityRegistry), address(s_credentialRegistry));
    assertEq(s_policy.getGroupSources(GROUP_PERSON, CREDENTIAL_KYC).length, 0);

    s_policy.addGroupSource(
      GROUP_PERSON, CREDENTIAL_KYC, address(s_identityRegistry), address(s_credentialRegistry), address(0)
    );
    assertEq(s_policy.getGroupSources(GROUP_PERSON, CREDENTIAL_KYC).length, 1);

    s_policy.removeGroup(GROUP_PERSON);
    s_policy.addGroup(
      IGroupedCredentialRequirements.GroupInput(
        GROUP_PERSON,
        _singletonType(CREDENTIAL_KYC),
        IGroupedCredentialRequirements.RoutingKind.Attestation,
        new bytes32[](0),
        1
      )
    );
    assertEq(s_policy.getGroupSources(GROUP_PERSON, CREDENTIAL_KYC).length, 0);
  }

  // source configuration input sanitisation

  function test_addGroupSource_revertsOnZeroIdentityRegistry() public {
    _addAttestationGroup(GROUP_PERSON, CREDENTIAL_KYC, false);
    vm.expectRevert(
      abi.encodeWithSelector(
        ICredentialRequirements.InvalidRequirementConfiguration.selector, "identityRegistry cannot be address(0)"
      )
    );
    s_policy.addGroupSource(GROUP_PERSON, CREDENTIAL_KYB, address(0), address(s_credentialRegistry), address(0));
  }

  function test_addGroupSource_revertsOnZeroCredentialRegistry() public {
    _addAttestationGroup(GROUP_PERSON, CREDENTIAL_KYC, false);
    vm.expectRevert(
      abi.encodeWithSelector(
        ICredentialRequirements.InvalidRequirementConfiguration.selector, "credentialRegistry cannot be address(0)"
      )
    );
    s_policy.addGroupSource(GROUP_PERSON, CREDENTIAL_KYB, address(s_identityRegistry), address(0), address(0));
  }

  function test_addGroupSource_revertsOnZeroCredentialTypeId() public {
    _addAttestationGroup(GROUP_PERSON, CREDENTIAL_KYC, false);
    vm.expectRevert(
      abi.encodeWithSelector(
        ICredentialRequirements.InvalidRequirementConfiguration.selector, "credentialTypeId cannot be 0"
      )
    );
    s_policy.addGroupSource(
      GROUP_PERSON, bytes32(0), address(s_identityRegistry), address(s_credentialRegistry), address(0)
    );
  }

  function test_addGroupSource_revertsOnNonContractDataValidator() public {
    _addAttestationGroup(GROUP_PERSON, CREDENTIAL_KYC, false);
    vm.expectRevert(
      abi.encodeWithSelector(
        ICredentialRequirements.InvalidRequirementConfiguration.selector, "dataValidator is not a contract"
      )
    );
    s_policy.addGroupSource(
      GROUP_PERSON, CREDENTIAL_KYB, address(s_identityRegistry), address(s_credentialRegistry), makeAddr("eoa")
    );
  }

  // zero-valued requirement identifiers are rejected

  function test_addGroupRequirement_revertsOnZeroRequirementId() public {
    _addAttestationGroup(GROUP_PERSON, CREDENTIAL_KYC, false);
    vm.expectRevert(
      abi.encodeWithSelector(
        ICredentialRequirements.InvalidRequirementConfiguration.selector, "requirementId cannot be 0"
      )
    );
    s_policy.addGroupRequirement(GROUP_PERSON, bytes32(0), _singletonType(CREDENTIAL_KYC), 1, false);
  }

  // inverted requirement parity with flat validator for accounts without identity

  function test_invertedRequirement_missingIdentity_countsAsValidation() public {
    // Account routes via KYC attestation, then must satisfy an inverted requirement on KYB whose
    // source points to a registry where the account has no identity.
    IdentityRegistry identityB = _deployIdentityRegistry(address(s_policyEngine));
    CredentialRegistry credentialB = _deployCredentialRegistry(address(s_policyEngine));

    _addAttestationGroup(GROUP_PERSON, CREDENTIAL_KYC, false);
    s_policy.addGroupSource(GROUP_PERSON, CREDENTIAL_KYB, address(identityB), address(credentialB), address(0));
    s_policy.addGroupRequirement(GROUP_PERSON, REQUIREMENT_KYC, _singletonType(CREDENTIAL_KYB), 1, true);

    address account = makeAddr("account");
    bytes32 ccid = keccak256("account");
    s_identityRegistry.registerIdentity(ccid, account, "");
    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYC, 0, "", "");
    // account intentionally NOT registered in identityB -> missing identity for the inverted requirement.

    assertTrue(s_policy.validate(account, ""));
  }

  function test_nonInvertedRequirement_missingIdentity_fails() public {
    // Control for the inverted case: a non-inverted requirement is not satisfied by a missing identity.
    IdentityRegistry identityB = _deployIdentityRegistry(address(s_policyEngine));
    CredentialRegistry credentialB = _deployCredentialRegistry(address(s_policyEngine));

    _addAttestationGroup(GROUP_PERSON, CREDENTIAL_KYC, false);
    s_policy.addGroupSource(GROUP_PERSON, CREDENTIAL_KYB, address(identityB), address(credentialB), address(0));
    s_policy.addGroupRequirement(GROUP_PERSON, REQUIREMENT_KYC, _singletonType(CREDENTIAL_KYB), 1, false);

    address account = makeAddr("account");
    bytes32 ccid = keccak256("account");
    s_identityRegistry.registerIdentity(ccid, account, "");
    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYC, 0, "", "");

    assertFalse(s_policy.validate(account, ""));
  }

  function _deployGroupedPolicyOwnedByEngine() internal returns (GroupedIdentityValidatorPolicy) {
    GroupedIdentityValidatorPolicy impl = new GroupedIdentityValidatorPolicy();
    bytes memory data =
      abi.encodeWithSelector(Policy.initialize.selector, address(s_policyEngine), address(s_policyEngine), "");
    ERC1967Proxy proxy = new ERC1967Proxy(address(impl), data);
    return GroupedIdentityValidatorPolicy(address(proxy));
  }

  function _deployGroupedPolicy(bytes memory parameters) internal returns (GroupedIdentityValidatorPolicy) {
    GroupedIdentityValidatorPolicy impl = new GroupedIdentityValidatorPolicy();
    bytes memory data =
      abi.encodeWithSelector(Policy.initialize.selector, address(s_policyEngine), address(this), parameters);
    ERC1967Proxy proxy = new ERC1967Proxy(address(impl), data);
    return GroupedIdentityValidatorPolicy(address(proxy));
  }

  function _addAttestationGroup(bytes32 groupId, bytes32 credentialTypeId, bool includeRequirement) internal {
    _addAttestationGroup(groupId, credentialTypeId, includeRequirement, 1);
  }

  function _addAttestationGroup(
    bytes32 groupId,
    bytes32 credentialTypeId,
    bool includeRequirement,
    uint256 routingMinValidations
  )
    internal
  {
    s_policy.addGroup(
      IGroupedCredentialRequirements.GroupInput(
        groupId,
        _singletonType(credentialTypeId),
        IGroupedCredentialRequirements.RoutingKind.Attestation,
        new bytes32[](0),
        routingMinValidations
      )
    );
    s_policy.addGroupSource(
      groupId, credentialTypeId, address(s_identityRegistry), address(s_credentialRegistry), address(0)
    );
    if (includeRequirement) {
      s_policy.addGroupRequirement(groupId, REQUIREMENT_KYC, _singletonType(credentialTypeId), 1, false);
    }
  }

  function _singletonType(bytes32 credentialTypeId) internal pure returns (bytes32[] memory ids) {
    ids = new bytes32[](1);
    ids[0] = credentialTypeId;
  }

  function _addDataRoutingGroup(bytes32 groupId, bytes32 credentialTypeId, bytes memory acceptedData) internal {
    bytes32[] memory criteria = new bytes32[](1);
    criteria[0] = keccak256(abi.encode(acceptedData));

    s_policy.addGroup(
      IGroupedCredentialRequirements.GroupInput(
        groupId, _singletonType(credentialTypeId), IGroupedCredentialRequirements.RoutingKind.Data, criteria, 1
      )
    );
    s_policy.addGroupSource(
      groupId, credentialTypeId, address(s_identityRegistry), address(s_credentialRegistry), address(0)
    );
  }
}
