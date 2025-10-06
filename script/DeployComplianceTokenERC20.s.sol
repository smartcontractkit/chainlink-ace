// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {ComplianceTokenERC20} from "../packages/tokens/erc-20/src/ComplianceTokenERC20.sol";
import {PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {Policy} from "@chainlink/policy-management/core/Policy.sol";
import {OnlyOwnerPolicy} from "@chainlink/policy-management/policies/OnlyOwnerPolicy.sol";
import {IdentityRegistry} from "@chainlink/cross-chain-identity/IdentityRegistry.sol";
import {CredentialRegistry} from "@chainlink/cross-chain-identity/CredentialRegistry.sol";
import {CredentialRegistryIdentityValidatorPolicy} from
  "@chainlink/cross-chain-identity/CredentialRegistryIdentityValidatorPolicy.sol";
import {ICredentialRequirements} from "@chainlink/cross-chain-identity/interfaces/ICredentialRequirements.sol";

import {ERC20TransferExtractor} from "@chainlink/policy-management/extractors/ERC20TransferExtractor.sol";
import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

contract DeployComplianceTokenERC20 is Script {
  function run() external {
    uint256 tokenOwnerPK = vm.envUint("PRIVATE_KEY");
    address tokenOwner = vm.addr(tokenOwnerPK);

    vm.startBroadcast(tokenOwnerPK);

    // Deploy a PolicyEngine through proxy for identity registries and attach OnlyOwnerPolicy to administrative methods
    PolicyEngine policyEngineImpl = new PolicyEngine();
    bytes memory policyEngineData =
      abi.encodeWithSelector(PolicyEngine.initialize.selector, IPolicyEngine.PolicyResult.Allowed);
    ERC1967Proxy policyEngineProxy = new ERC1967Proxy(address(policyEngineImpl), policyEngineData);
    PolicyEngine policyEngine = PolicyEngine(address(policyEngineProxy));

    // Deploy IdentityRegistry/CredentialRegistry through proxies for use by the
    // CredentialRegistryIdentityValidatorPolicy
    IdentityRegistry identityRegistryImpl = new IdentityRegistry();
    bytes memory identityRegistryData =
      abi.encodeWithSelector(IdentityRegistry.initialize.selector, address(policyEngine));
    ERC1967Proxy identityRegistryProxy = new ERC1967Proxy(address(identityRegistryImpl), identityRegistryData);
    IdentityRegistry identityRegistry = IdentityRegistry(address(identityRegistryProxy));

    CredentialRegistry credentialRegistryImpl = new CredentialRegistry();
    bytes memory credentialRegistryData =
      abi.encodeWithSelector(CredentialRegistry.initialize.selector, address(policyEngine));
    ERC1967Proxy credentialRegistryProxy = new ERC1967Proxy(address(credentialRegistryImpl), credentialRegistryData);
    CredentialRegistry credentialRegistry = CredentialRegistry(address(credentialRegistryProxy));

    bytes32 CREDENTIAL_KYC = keccak256("common.KYC");
    bytes32[] memory requiredCredentials = new bytes32[](1);
    requiredCredentials[0] = CREDENTIAL_KYC;

    ICredentialRequirements.CredentialRequirementInput[] memory credentialRequirementInputs =
      new ICredentialRequirements.CredentialRequirementInput[](1);
    credentialRequirementInputs[0] =
      ICredentialRequirements.CredentialRequirementInput(keccak256("requirement.KYC"), requiredCredentials, 1, false);

    ICredentialRequirements.CredentialSourceInput[] memory credentialSourceInputs =
      new ICredentialRequirements.CredentialSourceInput[](1);
    credentialSourceInputs[0] = ICredentialRequirements.CredentialSourceInput(
      CREDENTIAL_KYC, address(identityRegistry), address(credentialRegistry), address(0)
    );

    OnlyOwnerPolicy identityOnlyOwnerPolicyImpl = new OnlyOwnerPolicy();
    bytes memory onlyOwnerPolicyData =
      abi.encodeWithSelector(Policy.initialize.selector, address(policyEngine), tokenOwner, new bytes(0));
    ERC1967Proxy identityOnlyOwnerPolicyProxy =
      new ERC1967Proxy(address(identityOnlyOwnerPolicyImpl), onlyOwnerPolicyData);
    OnlyOwnerPolicy identityOnlyOwnerPolicy = OnlyOwnerPolicy(address(identityOnlyOwnerPolicyProxy));
    policyEngine.addPolicy(
      address(identityRegistry),
      IdentityRegistry.registerIdentity.selector,
      address(identityOnlyOwnerPolicy),
      new bytes32[](0)
    );
    policyEngine.addPolicy(
      address(identityRegistry),
      IdentityRegistry.registerIdentities.selector,
      address(identityOnlyOwnerPolicy),
      new bytes32[](0)
    );
    policyEngine.addPolicy(
      address(identityRegistry),
      IdentityRegistry.removeIdentity.selector,
      address(identityOnlyOwnerPolicy),
      new bytes32[](0)
    );
    policyEngine.addPolicy(
      address(credentialRegistry),
      CredentialRegistry.registerCredential.selector,
      address(identityOnlyOwnerPolicy),
      new bytes32[](0)
    );
    policyEngine.addPolicy(
      address(credentialRegistry),
      CredentialRegistry.registerCredentials.selector,
      address(identityOnlyOwnerPolicy),
      new bytes32[](0)
    );
    policyEngine.addPolicy(
      address(credentialRegistry),
      CredentialRegistry.removeCredential.selector,
      address(identityOnlyOwnerPolicy),
      new bytes32[](0)
    );
    policyEngine.addPolicy(
      address(credentialRegistry),
      CredentialRegistry.renewCredential.selector,
      address(identityOnlyOwnerPolicy),
      new bytes32[](0)
    );

    // Deploy the ComplianceTokenERC20 through proxy
    ComplianceTokenERC20 tokenImpl = new ComplianceTokenERC20();
    bytes memory tokenData = abi.encodeWithSelector(
      ComplianceTokenERC20.initialize.selector,
      vm.envOr("TOKEN_NAME", string("Token")),
      vm.envOr("TOKEN_SYMBOL", string("TOKEN")),
      18,
      address(policyEngine)
    );
    ERC1967Proxy tokenProxy = new ERC1967Proxy(address(tokenImpl), tokenData);
    ComplianceTokenERC20 token = ComplianceTokenERC20(address(tokenProxy));

    OnlyOwnerPolicy tokenOnlyOwnerPolicyImpl = new OnlyOwnerPolicy();
    bytes memory tokenOnlyOwnerPolicyData =
      abi.encodeWithSelector(Policy.initialize.selector, address(policyEngine), tokenOwner, new bytes(0));
    ERC1967Proxy tokenOnlyOwnerPolicyProxy =
      new ERC1967Proxy(address(tokenOnlyOwnerPolicyImpl), tokenOnlyOwnerPolicyData);
    OnlyOwnerPolicy tokenOnlyOwnerPolicy = OnlyOwnerPolicy(address(tokenOnlyOwnerPolicyProxy));
    policyEngine.addPolicy(
      address(token), ComplianceTokenERC20.mint.selector, address(tokenOnlyOwnerPolicy), new bytes32[](0)
    );
    policyEngine.addPolicy(
      address(token), ComplianceTokenERC20.burnFrom.selector, address(tokenOnlyOwnerPolicy), new bytes32[](0)
    );
    policyEngine.addPolicy(
      address(token), ComplianceTokenERC20.forceTransfer.selector, address(tokenOnlyOwnerPolicy), new bytes32[](0)
    );
    policyEngine.addPolicy(
      address(token), ComplianceTokenERC20.freeze.selector, address(tokenOnlyOwnerPolicy), new bytes32[](0)
    );
    policyEngine.addPolicy(
      address(token), ComplianceTokenERC20.unfreeze.selector, address(tokenOnlyOwnerPolicy), new bytes32[](0)
    );

    // Attach an CredentialRegistryIdentityValidatorPolicy to validate the 'to' address of ERC20 transfers
    ERC20TransferExtractor erc20TransferExtractor = new ERC20TransferExtractor();
    policyEngine.setExtractor(ComplianceTokenERC20.transfer.selector, address(erc20TransferExtractor));
    policyEngine.setExtractor(ComplianceTokenERC20.transferFrom.selector, address(erc20TransferExtractor));

    CredentialRegistryIdentityValidatorPolicy identityValidatorPolicyImpl =
      new CredentialRegistryIdentityValidatorPolicy();
    bytes memory identityValidatorPolicyData = abi.encodeWithSelector(
      Policy.initialize.selector,
      address(policyEngine),
      address(tokenOwner),
      abi.encode(credentialSourceInputs, credentialRequirementInputs)
    );
    ERC1967Proxy identityValidatorPolicyProxy =
      new ERC1967Proxy(address(identityValidatorPolicyImpl), identityValidatorPolicyData);
    CredentialRegistryIdentityValidatorPolicy identityValidatorPolicy =
      CredentialRegistryIdentityValidatorPolicy(address(identityValidatorPolicyProxy));
    bytes32[] memory identityValidatorPolicyParameters = new bytes32[](1);
    identityValidatorPolicyParameters[0] = erc20TransferExtractor.PARAM_TO();
    // Attach the CredentialRegistryIdentityValidatorPolicy to the transfer methods, using the IdentityValidator for
    // validations
    policyEngine.addPolicy(
      address(token),
      ComplianceTokenERC20.transfer.selector,
      address(identityValidatorPolicy),
      identityValidatorPolicyParameters
    );
    policyEngine.addPolicy(
      address(token),
      ComplianceTokenERC20.transferFrom.selector,
      address(identityValidatorPolicy),
      identityValidatorPolicyParameters
    );

    vm.stopBroadcast();

    console.log("Deployed ComplianceTokenERC20 at:", address(token));
    console.log("Deployed PolicyEngine at:", address(policyEngine));
    console.log("Deployed IdentityRegistry at:", address(identityRegistry));
    console.log("Deployed CredentialRegistry at:", address(credentialRegistry));
    console.log("Deployed Identity OnlyOwnerPolicy at:", address(identityOnlyOwnerPolicy));
    console.log("Deployed Token OnlyOwnerPolicy at:", address(tokenOnlyOwnerPolicy));
    console.log("Deployed ERC20TransferExtractor at:", address(erc20TransferExtractor));
    console.log("Deployed CredentialRegistryIdentityValidatorPolicy at:", address(identityValidatorPolicy));
  }
}
