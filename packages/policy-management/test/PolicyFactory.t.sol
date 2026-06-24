// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {PolicyEngine} from "../src/core/PolicyEngine.sol";
import {PolicyFactory} from "../src/core/PolicyFactory.sol";
import {PolicyAlwaysAllowed} from "./helpers/PolicyAlwaysAllowed.sol";
import {
  CredentialRegistryIdentityValidatorPolicy
} from "../../cross-chain-identity/src/CredentialRegistryIdentityValidatorPolicy.sol";
import {ICredentialRequirements} from "../../cross-chain-identity/src/interfaces/ICredentialRequirements.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @dev ERC-165 contract that does not declare support for IPolicy
contract NonPolicyImplementation is IERC165 {
  function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
    return interfaceId == type(IERC165).interfaceId;
  }
}

contract PolicyFactoryTest is Test {
  PolicyEngine private s_policyEngine;
  PolicyFactory private s_factory;

  address public owner = makeAddr("owner");

  PolicyAlwaysAllowed private s_policyImplementation;

  bytes32 public constant REQUIREMENT_KYC = keccak256("KYC");
  bytes32 public constant CREDENTIAL_KYC = keccak256("common.kyc");

  function setUp() public {
    vm.startPrank(owner);

    s_policyEngine = new PolicyEngine();
    s_factory = new PolicyFactory();
    s_policyImplementation = new PolicyAlwaysAllowed();
  }

  function test_createPolicy_success() public {
    bytes32 policyId = keccak256(abi.encodePacked("policy-1"));
    bytes memory configData = abi.encode(42);

    address expectedPolicyAddress = s_factory.predictPolicyAddress(owner, address(s_policyImplementation), policyId);

    vm.expectEmit();
    emit PolicyFactory.PolicyCreated(expectedPolicyAddress);

    address newPolicyAddress =
      s_factory.createPolicy(address(s_policyImplementation), policyId, address(s_policyEngine), owner, configData);
    assertEq(newPolicyAddress, expectedPolicyAddress);

    PolicyAlwaysAllowed newPolicy = PolicyAlwaysAllowed(newPolicyAddress);
    assertEq(newPolicy.getPolicyNumber(), 42);
  }

  function test_createUpgradeablePolicy_success() public {
    bytes32 policyId = keccak256(abi.encodePacked("policy-1"));
    bytes memory configData = abi.encode(42);

    address expectedPolicyAddress = s_factory.predictUpgradeablePolicyAddress(
      owner, address(s_policyImplementation), policyId, address(s_policyEngine), owner, configData
    );

    vm.expectEmit();
    emit PolicyFactory.PolicyCreated(expectedPolicyAddress);

    address newPolicyAddress = s_factory.createUpgradeablePolicy(
      address(s_policyImplementation), policyId, address(s_policyEngine), owner, configData
    );
    assertEq(newPolicyAddress, expectedPolicyAddress);

    PolicyAlwaysAllowed newPolicy = PolicyAlwaysAllowed(newPolicyAddress);
    assertEq(newPolicy.getPolicyNumber(), 42);
  }

  function test_createUpgradeablePolicy_upgrade_success() public {
    bytes32 policyId = keccak256(abi.encodePacked("policy-1"));
    bytes memory configData = abi.encode(42);
    address owner = makeAddr("owner");

    address newPolicyAddress = s_factory.createUpgradeablePolicy(
      address(s_policyImplementation), policyId, address(s_policyEngine), owner, configData
    );
    PolicyAlwaysAllowed policy = PolicyAlwaysAllowed(newPolicyAddress);
    assertEq(policy.owner(), owner);

    PolicyAlwaysAllowed newImplementation = new PolicyAlwaysAllowed();

    vm.startPrank(owner);
    policy.upgradeToAndCall(address(newImplementation), "");

    // Verify that the engine still has the same state after the upgrade
    assertEq(policy.owner(), owner);
  }

  function test_createUpgradeablePolicy_upgradeNotOwner_revert() public {
    bytes32 policyId = keccak256(abi.encodePacked("policy-1"));
    bytes memory configData = abi.encode(42);
    address owner = makeAddr("owner");
    address notOwner = makeAddr("notOwner");

    address newPolicyAddress = s_factory.createUpgradeablePolicy(
      address(s_policyImplementation), policyId, address(s_policyEngine), owner, configData
    );
    PolicyAlwaysAllowed policy = PolicyAlwaysAllowed(newPolicyAddress);

    PolicyAlwaysAllowed newImplementation = new PolicyAlwaysAllowed();

    vm.startPrank(notOwner);
    vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, notOwner));
    policy.upgradeToAndCall(address(newImplementation), "");
  }

  function test_createPolicy_duplicateCreate_reverts() public {
    bytes32 policyId = keccak256(abi.encodePacked("policy-1"));
    bytes memory configData = abi.encode(42);

    address expectedPolicyAddress = s_factory.predictPolicyAddress(owner, address(s_policyImplementation), policyId);

    vm.expectEmit();
    emit PolicyFactory.PolicyCreated(expectedPolicyAddress);
    s_factory.createPolicy(address(s_policyImplementation), policyId, address(s_policyEngine), owner, configData);

    vm.expectRevert(PolicyFactory.PolicyAlreadyExists.selector);
    s_factory.createPolicy(address(s_policyImplementation), policyId, address(s_policyEngine), owner, configData);
  }

  function test_getOrCreatePolicy_duplicateCreate_success() public {
    bytes32 policyId = keccak256(abi.encodePacked("policy-1"));
    bytes memory configData = abi.encode(42);

    address expectedPolicyAddress = s_factory.predictPolicyAddress(owner, address(s_policyImplementation), policyId);

    vm.expectEmit();
    emit PolicyFactory.PolicyCreated(expectedPolicyAddress);

    address newPolicyAddress = s_factory.getOrCreatePolicy(
      address(s_policyImplementation), policyId, address(s_policyEngine), owner, configData
    );
    address newPolicyAddress2 = s_factory.getOrCreatePolicy(
      address(s_policyImplementation), policyId, address(s_policyEngine), owner, configData
    );
    assertEq(newPolicyAddress, newPolicyAddress2);
  }

  function test_createPolicy_badconfigData_revert() public {
    bytes32 policyId = keccak256(abi.encodePacked("policy-1"));

    vm.expectPartialRevert(PolicyFactory.PolicyInitializationFailed.selector);
    s_factory.createPolicy(address(s_policyImplementation), policyId, address(s_policyEngine), owner, "0x1234");
  }

  function test_createPolicy_nonPolicyImplementation_reverts() public {
    NonPolicyImplementation badImpl = new NonPolicyImplementation();

    vm.expectRevert(PolicyFactory.ImplementationDoesNotSupportIPolicy.selector);
    s_factory.createPolicy(
      address(badImpl),
      keccak256(abi.encodePacked("implementation that does not support IPolicy")),
      address(s_policyEngine),
      owner,
      abi.encode(0)
    );
  }

  function test_createUpgradeablePolicy_nonPolicyImplementation_reverts() public {
    NonPolicyImplementation badImpl = new NonPolicyImplementation();

    vm.expectRevert(PolicyFactory.ImplementationDoesNotSupportIPolicy.selector);
    s_factory.createUpgradeablePolicy(
      address(badImpl),
      keccak256(abi.encodePacked("upgradeable implementation that does not support IPolicy")),
      address(s_policyEngine),
      owner,
      abi.encode(0)
    );
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

    address expectedPolicyAddress = s_factory.predictPolicyAddress(owner, address(identityValidatorPolicy), policyId);

    vm.expectEmit();
    emit PolicyFactory.PolicyCreated(expectedPolicyAddress);

    address newPolicyAddress =
      s_factory.createPolicy(address(identityValidatorPolicy), policyId, address(s_policyEngine), owner, configData);
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
