// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {IERC7943Fungible} from "../packages/tokens/erc-7943/src/interfaces/IERC7943.sol";
import {ComplianceTokenERC7943} from "../packages/tokens/erc-7943/src/ComplianceTokenERC7943.sol";
import {PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {Policy} from "@chainlink/policy-management/core/Policy.sol";
import {OnlyOwnerPolicy} from "@chainlink/policy-management/policies/OnlyOwnerPolicy.sol";
import {IdentityRegistry} from "@chainlink/cross-chain-identity/IdentityRegistry.sol";
import {CredentialRegistry} from "@chainlink/cross-chain-identity/CredentialRegistry.sol";
import {CredentialRegistryIdentityValidatorPolicy} from
  "@chainlink/cross-chain-identity/CredentialRegistryIdentityValidatorPolicy.sol";
import {ICredentialRequirements} from "@chainlink/cross-chain-identity/interfaces/ICredentialRequirements.sol";

import {ERC20TransferExtractor} from "@chainlink/policy-management/extractors/ERC20TransferExtractor.sol";
import {ERC7943MintBurnExtractor} from "@chainlink/policy-management/extractors/ERC7943MintBurnExtractor.sol";
import {ERC7943ForcedTransferExtractor} from "@chainlink/policy-management/extractors/ERC7943ForcedTransferExtractor.sol";
import {ERC7943SetFrozenTokensExtractor} from
  "@chainlink/policy-management/extractors/ERC7943SetFrozenTokensExtractor.sol";
import {ERC7943WhitelistExtractor} from "@chainlink/policy-management/extractors/ERC7943WhitelistExtractor.sol";
import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

contract DeployComplianceTokenERC7943 is Script {
  function run() external {
    uint256 tokenOwnerPK = vm.envUint("PRIVATE_KEY");
    address tokenOwner = vm.addr(tokenOwnerPK);

    vm.startBroadcast(tokenOwnerPK);

    // Deploy a PolicyEngine through proxy for identity registries and attach OnlyOwnerPolicy to administrative methods
    PolicyEngine policyEngineImpl = new PolicyEngine();
    bytes memory policyEngineData =
      abi.encodeWithSelector(PolicyEngine.initialize.selector, IPolicyEngine.PolicyResult.Allowed, tokenOwner);
    ERC1967Proxy policyEngineProxy = new ERC1967Proxy(address(policyEngineImpl), policyEngineData);
    PolicyEngine policyEngine = PolicyEngine(address(policyEngineProxy));

    // Deploy IdentityRegistry/CredentialRegistry through proxies for use by the
    // CredentialRegistryIdentityValidatorPolicy
    IdentityRegistry identityRegistryImpl = new IdentityRegistry();
    bytes memory identityRegistryData =
      abi.encodeWithSelector(IdentityRegistry.initialize.selector, address(policyEngine), tokenOwner);
    ERC1967Proxy identityRegistryProxy = new ERC1967Proxy(address(identityRegistryImpl), identityRegistryData);
    IdentityRegistry identityRegistry = IdentityRegistry(address(identityRegistryProxy));

    CredentialRegistry credentialRegistryImpl = new CredentialRegistry();
    bytes memory credentialRegistryData =
      abi.encodeWithSelector(CredentialRegistry.initialize.selector, address(policyEngine), tokenOwner);
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

    // Deploy the ComplianceTokenERC7943 through proxy
    ComplianceTokenERC7943 tokenImpl = new ComplianceTokenERC7943();
    bytes memory tokenData = abi.encodeWithSelector(
      ComplianceTokenERC7943.initialize.selector,
      vm.envOr("TOKEN_NAME", string("Token")),
      vm.envOr("TOKEN_SYMBOL", string("TOKEN")),
      18,
      address(policyEngine)
    );
    ERC1967Proxy tokenProxy = new ERC1967Proxy(address(tokenImpl), tokenData);
    ComplianceTokenERC7943 token = ComplianceTokenERC7943(address(tokenProxy));

    // Deploy OnlyOwnerPolicy for token administrative methods
    OnlyOwnerPolicy tokenOnlyOwnerPolicyImpl = new OnlyOwnerPolicy();
    bytes memory tokenOnlyOwnerPolicyData =
      abi.encodeWithSelector(Policy.initialize.selector, address(policyEngine), tokenOwner, new bytes(0));
    ERC1967Proxy tokenOnlyOwnerPolicyProxy =
      new ERC1967Proxy(address(tokenOnlyOwnerPolicyImpl), tokenOnlyOwnerPolicyData);
    OnlyOwnerPolicy tokenOnlyOwnerPolicy = OnlyOwnerPolicy(address(tokenOnlyOwnerPolicyProxy));

    // Setup extractors for ERC7943 functions
    ERC7943MintBurnExtractor mintBurnExtractor = new ERC7943MintBurnExtractor();
    policyEngine.setExtractor(ComplianceTokenERC7943.mint.selector, address(mintBurnExtractor));
    policyEngine.setExtractor(ComplianceTokenERC7943.burn.selector, address(mintBurnExtractor));
    policyEngine.setExtractor(ComplianceTokenERC7943.burnFrom.selector, address(mintBurnExtractor));

    ERC7943ForcedTransferExtractor forcedTransferExtractor = new ERC7943ForcedTransferExtractor();
    policyEngine.setExtractor(IERC7943Fungible.forcedTransfer.selector, address(forcedTransferExtractor));

    ERC7943SetFrozenTokensExtractor setFrozenExtractor = new ERC7943SetFrozenTokensExtractor();
    policyEngine.setExtractor(IERC7943Fungible.setFrozenTokens.selector, address(setFrozenExtractor));

    ERC7943WhitelistExtractor whitelistExtractor = new ERC7943WhitelistExtractor();
    policyEngine.setExtractor(ComplianceTokenERC7943.changeWhitelist.selector, address(whitelistExtractor));

    // Attach OnlyOwnerPolicy to administrative token methods
    policyEngine.addPolicy(
      address(token), ComplianceTokenERC7943.mint.selector, address(tokenOnlyOwnerPolicy), new bytes32[](0)
    );
    policyEngine.addPolicy(
      address(token), ComplianceTokenERC7943.burnFrom.selector, address(tokenOnlyOwnerPolicy), new bytes32[](0)
    );
    policyEngine.addPolicy(
      address(token), IERC7943Fungible.forcedTransfer.selector, address(tokenOnlyOwnerPolicy), new bytes32[](0)
    );
    policyEngine.addPolicy(
      address(token), IERC7943Fungible.setFrozenTokens.selector, address(tokenOnlyOwnerPolicy), new bytes32[](0)
    );
    policyEngine.addPolicy(
      address(token), ComplianceTokenERC7943.changeWhitelist.selector, address(tokenOnlyOwnerPolicy), new bytes32[](0)
    );

    // Attach an CredentialRegistryIdentityValidatorPolicy to validate the 'to' address of ERC20 transfers
    ERC20TransferExtractor erc20TransferExtractor = new ERC20TransferExtractor();
    policyEngine.setExtractor(ComplianceTokenERC7943.transfer.selector, address(erc20TransferExtractor));
    policyEngine.setExtractor(ComplianceTokenERC7943.transferFrom.selector, address(erc20TransferExtractor));

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
      ComplianceTokenERC7943.transfer.selector,
      address(identityValidatorPolicy),
      identityValidatorPolicyParameters
    );
    policyEngine.addPolicy(
      address(token),
      ComplianceTokenERC7943.transferFrom.selector,
      address(identityValidatorPolicy),
      identityValidatorPolicyParameters
    );

    vm.stopBroadcast();

    console.log("Deployed ComplianceTokenERC7943 at:", address(token));
    console.log("Deployed PolicyEngine at:", address(policyEngine));
    console.log("Deployed IdentityRegistry at:", address(identityRegistry));
    console.log("Deployed CredentialRegistry at:", address(credentialRegistry));
    console.log("Deployed Identity OnlyOwnerPolicy at:", address(identityOnlyOwnerPolicy));
    console.log("Deployed Token OnlyOwnerPolicy at:", address(tokenOnlyOwnerPolicy));
    console.log("Deployed ERC20TransferExtractor at:", address(erc20TransferExtractor));
    console.log("Deployed ERC7943MintBurnExtractor at:", address(mintBurnExtractor));
    console.log("Deployed ERC7943ForcedTransferExtractor at:", address(forcedTransferExtractor));
    console.log("Deployed ERC7943SetFrozenTokensExtractor at:", address(setFrozenExtractor));
    console.log("Deployed ERC7943WhitelistExtractor at:", address(whitelistExtractor));
    console.log("Deployed CredentialRegistryIdentityValidatorPolicy at:", address(identityValidatorPolicy));
  }
}
