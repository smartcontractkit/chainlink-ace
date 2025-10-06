// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {PolicyEngine} from "../src/core/PolicyEngine.sol";
import {PolicyFactory} from "../src/core/PolicyFactory.sol";
import {PolicyAlwaysAllowed} from "./helpers/PolicyAlwaysAllowed.sol";
import {CredentialRegistryIdentityValidatorPolicy} from
  "@chainlink/cross-chain-identity/CredentialRegistryIdentityValidatorPolicy.sol";
import {ICredentialRequirements} from "@chainlink/cross-chain-identity/interfaces/ICredentialRequirements.sol";
import {Test} from "forge-std/Test.sol";

contract PolicyFactoryTest is Test {
  PolicyEngine private s_policyEngine;
  PolicyFactory private s_factory;

  PolicyAlwaysAllowed private s_policyImplementation;

  bytes32 public constant REQUIREMENT_KYC = keccak256("KYC");
  bytes32 public constant CREDENTIAL_KYC = keccak256("common.kyc");

  function setUp() public {
    s_policyEngine = new PolicyEngine();
    s_factory = new PolicyFactory();
    s_policyImplementation = new PolicyAlwaysAllowed();
  }

  function test_createPolicy_success() public {
    bytes32 policyId = keccak256(abi.encodePacked("policy-1"));
    bytes memory configData = abi.encode(42);

    address expectedPolicyAddress =
      s_factory.predictPolicyAddress(address(this), address(s_policyImplementation), policyId);

    vm.expectEmit();
    emit PolicyFactory.PolicyCreated(expectedPolicyAddress);

    address newPolicyAddress = s_factory.createPolicy(
      address(s_policyImplementation), policyId, address(s_policyEngine), address(this), configData
    );
    assertEq(newPolicyAddress, expectedPolicyAddress);

    PolicyAlwaysAllowed newPolicy = PolicyAlwaysAllowed(newPolicyAddress);
    assertEq(newPolicy.getPolicyNumber(), 42);
  }

  function test_createPolicy_duplicateCreate_success() public {
    bytes32 policyId = keccak256(abi.encodePacked("policy-1"));
    bytes memory configData = abi.encode(42);

    address expectedPolicyAddress =
      s_factory.predictPolicyAddress(address(this), address(s_policyImplementation), policyId);

    vm.expectEmit();
    emit PolicyFactory.PolicyCreated(expectedPolicyAddress);

    address newPolicyAddress = s_factory.createPolicy(
      address(s_policyImplementation), policyId, address(s_policyEngine), address(this), configData
    );
    address newPolicyAddress2 = s_factory.createPolicy(
      address(s_policyImplementation), policyId, address(s_policyEngine), address(this), configData
    );
    assertEq(newPolicyAddress, newPolicyAddress2);
  }

  function test_createPolicy_badconfigData_revert() public {
    bytes32 policyId = keccak256(abi.encodePacked("policy-1"));

    vm.expectPartialRevert(PolicyFactory.PolicyInitializationFailed.selector);
    s_factory.createPolicy(address(s_policyImplementation), policyId, address(s_policyEngine), address(this), "0x1234");
  }

  function test_createCredentialRegistryIdentityValidatorPolicy_success() public {
    bytes32 policyId = keccak256(abi.encodePacked("policy-1"));
    address identityRegistry = vm.addr(uint256(keccak256(abi.encodePacked(block.timestamp, "identity"))));
    address credentialRegistry = vm.addr(uint256(keccak256(abi.encodePacked(block.timestamp, "credential"))));
    bytes32[] memory credentialsKyc = new bytes32[](1);
    credentialsKyc[0] = CREDENTIAL_KYC;

    ICredentialRequirements.CredentialRequirementInput[] memory requirementsInput =
      new ICredentialRequirements.CredentialRequirementInput[](1);
    requirementsInput[0] = ICredentialRequirements.CredentialRequirementInput(REQUIREMENT_KYC, credentialsKyc, 1, false);

    ICredentialRequirements.CredentialSourceInput[] memory sourceInputs =
      new ICredentialRequirements.CredentialSourceInput[](1);

    sourceInputs[0] =
      ICredentialRequirements.CredentialSourceInput(CREDENTIAL_KYC, identityRegistry, credentialRegistry, address(0));

    bytes memory configData = abi.encode(sourceInputs, requirementsInput);

    CredentialRegistryIdentityValidatorPolicy identityValidatorPolicy = new CredentialRegistryIdentityValidatorPolicy();

    address expectedPolicyAddress =
      s_factory.predictPolicyAddress(address(this), address(identityValidatorPolicy), policyId);

    vm.expectEmit();
    emit PolicyFactory.PolicyCreated(expectedPolicyAddress);

    address newPolicyAddress = s_factory.createPolicy(
      address(identityValidatorPolicy), policyId, address(s_policyEngine), address(this), configData
    );
    assertEq(newPolicyAddress, expectedPolicyAddress);

    CredentialRegistryIdentityValidatorPolicy deployedPolicy =
      CredentialRegistryIdentityValidatorPolicy(newPolicyAddress);
    ICredentialRequirements.CredentialSource[] memory credentialSources =
      deployedPolicy.getCredentialSources(CREDENTIAL_KYC);
    assertEq(credentialSources.length, 1);
    assertEq(credentialSources[0].identityRegistry, identityRegistry);
    bytes32[] memory credentialRequirementIds = deployedPolicy.getCredentialRequirementIds();
    assertEq(credentialRequirementIds.length, 1);
    assertEq(credentialRequirementIds[0], REQUIREMENT_KYC);
  }
}
