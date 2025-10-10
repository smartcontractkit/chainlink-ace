// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {ICredentialRequirements} from "../src/interfaces/ICredentialRequirements.sol";
import {IdentityRegistry} from "../src/IdentityRegistry.sol";
import {CredentialRegistry} from "../src/CredentialRegistry.sol";
import {CredentialRegistryIdentityValidatorPolicy} from "../src/CredentialRegistryIdentityValidatorPolicy.sol";
import {PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {BaseProxyTest} from "./helpers/BaseProxyTest.sol";

contract CredentialRegistryIdentityValidatorPolicyTest is BaseProxyTest {
  bytes32 public constant REQUIREMENT_KYC = keccak256("KYC");
  bytes32 public constant CREDENTIAL_KYC = keccak256("common.kyc");

  bytes32[] internal s_credentials_kyc;

  PolicyEngine internal s_policyEngine;
  IdentityRegistry internal s_identityRegistry;
  CredentialRegistry internal s_credentialRegistry;
  CredentialRegistryIdentityValidatorPolicy internal s_identityValidatorPolicy;

  address internal s_owner;

  function setUp() public {
    s_owner = makeAddr("owner");

    vm.startPrank(s_owner);

    s_credentials_kyc = new bytes32[](1);
    s_credentials_kyc[0] = CREDENTIAL_KYC;

    s_policyEngine = _deployPolicyEngine(true, address(this));
    s_identityRegistry = _deployIdentityRegistry(address(s_policyEngine));
    s_credentialRegistry = _deployCredentialRegistry(address(s_policyEngine));

    ICredentialRequirements.CredentialRequirementInput[] memory credentialRequirementInputs =
      new ICredentialRequirements.CredentialRequirementInput[](1);
    credentialRequirementInputs[0] =
      ICredentialRequirements.CredentialRequirementInput(REQUIREMENT_KYC, s_credentials_kyc, 1, false);

    ICredentialRequirements.CredentialSourceInput[] memory credentialSourceInputs =
      new ICredentialRequirements.CredentialSourceInput[](1);

    credentialSourceInputs[0] = ICredentialRequirements.CredentialSourceInput(
      CREDENTIAL_KYC, address(s_identityRegistry), address(s_credentialRegistry), address(0)
    );

    s_identityValidatorPolicy = _deployCredentialRegistryCredentialRegistryIdentityValidatorPolicy(
      address(s_policyEngine), s_owner, abi.encode(credentialSourceInputs, credentialRequirementInputs)
    );
  }

  function test_run_continue() public {
    address account1 = makeAddr("account1");
    bytes32 ccid = keccak256("account1");

    s_identityRegistry.registerIdentity(ccid, account1, "");
    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYC, 0, "", "");

    assertTrue(s_identityValidatorPolicy.validate(account1, ""));

    bytes[] memory parameters = new bytes[](1);
    parameters[0] = abi.encode(account1);

    IPolicyEngine.PolicyResult policyRes =
      s_identityValidatorPolicy.run(address(0), address(0), 0x00000000, parameters, "");
    assert(policyRes == IPolicyEngine.PolicyResult.Continue);
  }

  function test_run_rejected() public {
    address account1 = makeAddr("account1");
    bytes32 ccid = keccak256("account1");

    s_identityRegistry.registerIdentity(ccid, account1, "");

    assertFalse(s_identityValidatorPolicy.validate(account1, ""));

    bytes[] memory parameters = new bytes[](1);
    parameters[0] = abi.encode(account1);

    vm.expectPartialRevert(IPolicyEngine.PolicyRejected.selector);
    IPolicyEngine.PolicyResult policyRes =
      s_identityValidatorPolicy.run(address(0), address(0), 0x00000000, parameters, "");
  }

  function test_empty_initialization_and_later_configuration_continues() public {
    CredentialRegistryIdentityValidatorPolicy policy =
      _deployCredentialRegistryCredentialRegistryIdentityValidatorPolicy(address(s_policyEngine), s_owner, "");

    ICredentialRequirements.CredentialRequirementInput memory credentialRequirementInputs =
      ICredentialRequirements.CredentialRequirementInput(REQUIREMENT_KYC, s_credentials_kyc, 1, false);

    ICredentialRequirements.CredentialSourceInput memory credentialSourceInput = ICredentialRequirements
      .CredentialSourceInput(CREDENTIAL_KYC, address(s_identityRegistry), address(s_credentialRegistry), address(0));

    policy.addCredentialSource(credentialSourceInput);
    policy.addCredentialRequirement(credentialRequirementInputs);

    address account1 = makeAddr("account1");
    bytes32 ccid = keccak256("account1");

    s_identityRegistry.registerIdentity(ccid, account1, "");
    s_credentialRegistry.registerCredential(ccid, CREDENTIAL_KYC, 0, "", "");

    assertTrue(policy.validate(account1, ""));

    bytes[] memory parameters = new bytes[](1);
    parameters[0] = abi.encode(account1);

    IPolicyEngine.PolicyResult policyRes = policy.run(address(0), address(0), 0x00000000, parameters, "");
    assert(policyRes == IPolicyEngine.PolicyResult.Continue);
  }
}
