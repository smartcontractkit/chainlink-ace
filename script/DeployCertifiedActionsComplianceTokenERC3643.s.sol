// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {ComplianceTokenERC3643} from "../packages/tokens/erc-3643/src/ComplianceTokenERC3643.sol";
import {PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {Policy} from "@chainlink/policy-management/core/Policy.sol";
import {OnlyOwnerPolicy} from "@chainlink/policy-management/policies/OnlyOwnerPolicy.sol";
import {CertifiedActionDONValidatorPolicy} from
  "@chainlink/policy-management/policies/CertifiedActionDONValidatorPolicy.sol";
import {ICredentialRequirements} from "@chainlink/cross-chain-identity/interfaces/ICredentialRequirements.sol";
import {ERC20TransferExtractor} from "@chainlink/policy-management/extractors/ERC20TransferExtractor.sol";
import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

contract DeployCertifiedActionsComplianceTokenERC3643 is Script {
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

    // Deploy the ComplianceTokenERC3643 through proxy
    ComplianceTokenERC3643 tokenImpl = new ComplianceTokenERC3643();
    bytes memory tokenData = abi.encodeWithSelector(
      ComplianceTokenERC3643.initialize.selector,
      vm.envOr("TOKEN_NAME", string("Token")),
      vm.envOr("TOKEN_SYMBOL", string("TOKEN")),
      18,
      address(policyEngine)
    );
    ERC1967Proxy tokenProxy = new ERC1967Proxy(address(tokenImpl), tokenData);
    ComplianceTokenERC3643 token = ComplianceTokenERC3643(address(tokenProxy));

    OnlyOwnerPolicy tokenOnlyOwnerPolicyImpl = new OnlyOwnerPolicy();
    bytes memory tokenOnlyOwnerPolicyData =
      abi.encodeWithSelector(Policy.initialize.selector, address(policyEngine), tokenOwner, new bytes(0));
    ERC1967Proxy tokenOnlyOwnerPolicyProxy =
      new ERC1967Proxy(address(tokenOnlyOwnerPolicyImpl), tokenOnlyOwnerPolicyData);
    OnlyOwnerPolicy tokenOnlyOwnerPolicy = OnlyOwnerPolicy(address(tokenOnlyOwnerPolicyProxy));
    policyEngine.addPolicy(
      address(token), ComplianceTokenERC3643.mint.selector, address(tokenOnlyOwnerPolicy), new bytes32[](0)
    );
    policyEngine.addPolicy(
      address(token), ComplianceTokenERC3643.pause.selector, address(tokenOnlyOwnerPolicy), new bytes32[](0)
    );
    policyEngine.addPolicy(
      address(token), ComplianceTokenERC3643.unpause.selector, address(tokenOnlyOwnerPolicy), new bytes32[](0)
    );
    policyEngine.addPolicy(
      address(token), ComplianceTokenERC3643.setAddressFrozen.selector, address(tokenOnlyOwnerPolicy), new bytes32[](0)
    );
    policyEngine.addPolicy(
      address(token), ComplianceTokenERC3643.forcedTransfer.selector, address(tokenOnlyOwnerPolicy), new bytes32[](0)
    );
    policyEngine.addPolicy(
      address(token),
      ComplianceTokenERC3643.freezePartialTokens.selector,
      address(tokenOnlyOwnerPolicy),
      new bytes32[](0)
    );
    policyEngine.addPolicy(
      address(token),
      ComplianceTokenERC3643.unfreezePartialTokens.selector,
      address(tokenOnlyOwnerPolicy),
      new bytes32[](0)
    );
    policyEngine.addPolicy(
      address(token), ComplianceTokenERC3643.setName.selector, address(tokenOnlyOwnerPolicy), new bytes32[](0)
    );
    policyEngine.addPolicy(
      address(token), ComplianceTokenERC3643.setSymbol.selector, address(tokenOnlyOwnerPolicy), new bytes32[](0)
    );

    // Attach an CredentialRegistryIdentityValidatorPolicy to validate the 'to' address of ERC20 transfers
    ERC20TransferExtractor erc20TransferExtractor = new ERC20TransferExtractor();
    policyEngine.setExtractor(ComplianceTokenERC3643.transfer.selector, address(erc20TransferExtractor));
    policyEngine.setExtractor(ComplianceTokenERC3643.transferFrom.selector, address(erc20TransferExtractor));

    CertifiedActionDONValidatorPolicy certifiedActionDONValidatorPolicyImpl = new CertifiedActionDONValidatorPolicy();
    bytes memory certifiedActionDONValidatorPolicyData = abi.encodeWithSelector(
      Policy.initialize.selector,
      address(policyEngine),
      address(tokenOwner),
      abi.encode(vm.envAddress("KEYSTONE_FORWARDER_ADDRESS"))
    );
    ERC1967Proxy certifiedActionDONValidatorPolicyProxy =
      new ERC1967Proxy(address(certifiedActionDONValidatorPolicyImpl), certifiedActionDONValidatorPolicyData);
    CertifiedActionDONValidatorPolicy certifiedActionDONValidatorPolicy =
      CertifiedActionDONValidatorPolicy(address(certifiedActionDONValidatorPolicyProxy));
    bytes32[] memory certifiedActionDONValidatorPolicyParameters = new bytes32[](3);
    certifiedActionDONValidatorPolicyParameters[0] = erc20TransferExtractor.PARAM_FROM();
    certifiedActionDONValidatorPolicyParameters[1] = erc20TransferExtractor.PARAM_TO();
    certifiedActionDONValidatorPolicyParameters[2] = erc20TransferExtractor.PARAM_AMOUNT();

    policyEngine.addPolicy(
      address(token),
      ComplianceTokenERC3643.transfer.selector,
      address(certifiedActionDONValidatorPolicy),
      certifiedActionDONValidatorPolicyParameters
    );
    policyEngine.addPolicy(
      address(token),
      ComplianceTokenERC3643.transferFrom.selector,
      address(certifiedActionDONValidatorPolicy),
      certifiedActionDONValidatorPolicyParameters
    );

    vm.stopBroadcast();

    console.log("Deployed ComplianceTokenERC3643 at:", address(token));
    console.log("Deployed PolicyEngine at:", address(policyEngine));
    console.log("Deployed Token OnlyOwnerPolicy at:", address(tokenOnlyOwnerPolicy));
    console.log("Deployed ERC20TransferExtractor at:", address(erc20TransferExtractor));
    console.log("Deployed CertifiedActionDONValidatorPolicy at:", address(certifiedActionDONValidatorPolicy));
  }
}
