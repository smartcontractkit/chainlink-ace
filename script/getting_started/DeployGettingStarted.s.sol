// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {MyVault} from "../../getting_started/MyVault.sol";
import {PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {Policy} from "@chainlink/policy-management/core/Policy.sol";
import {PausePolicy} from "@chainlink/policy-management/policies/PausePolicy.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";

/**
 * @title DeployGettingStarted
 * @notice Deployment script for the Getting Started guide example.
 * @dev This script demonstrates the complete setup process:
 * 1. Deploy and initialize a PolicyEngine through a proxy
 * 2. Deploy the vault contract (connected to PolicyEngine via constructor)
 * 3. Deploy and configure a PausePolicy
 * 4. Attach the policy to the vault's deposit and withdraw functions
 */
contract DeployGettingStarted is Script {
  function run() external {
    uint256 deployerPK = vm.envUint("PRIVATE_KEY");
    address deployer = vm.addr(deployerPK);

    vm.startBroadcast(deployerPK);

    // 1. Deploy the PolicyEngine through a proxy
    PolicyEngine policyEngineImpl = new PolicyEngine();
    bytes memory policyEngineData = abi.encodeWithSelector(PolicyEngine.initialize.selector, true, deployer);
    ERC1967Proxy policyEngineProxy = new ERC1967Proxy(address(policyEngineImpl), policyEngineData);
    PolicyEngine policyEngine = PolicyEngine(address(policyEngineProxy));

    // 2. Deploy your vault through a proxy
    MyVault vaultImpl = new MyVault();
    bytes memory vaultData = abi.encodeWithSelector(MyVault.initialize.selector, deployer, address(policyEngine));
    ERC1967Proxy vaultProxy = new ERC1967Proxy(address(vaultImpl), vaultData);
    MyVault vault = MyVault(address(vaultProxy));

    // 3. Deploy the PausePolicy through a proxy
    PausePolicy pausePolicyImpl = new PausePolicy();
    bytes memory pausePolicyConfig = abi.encode(false); // Not paused by default
    bytes memory pausePolicyData =
      abi.encodeWithSelector(Policy.initialize.selector, address(policyEngine), deployer, pausePolicyConfig);
    ERC1967Proxy pausePolicyProxy = new ERC1967Proxy(address(pausePolicyImpl), pausePolicyData);
    PausePolicy pausePolicy = PausePolicy(address(pausePolicyProxy));

    // 4. Add the PausePolicy to the vault's deposit function
    policyEngine.addPolicy(
      address(vault),
      vault.deposit.selector,
      address(pausePolicy),
      new bytes32[](0) // No parameters needed for
        // PausePolicy
    );

    // 5. Add the PausePolicy to the vault's withdraw function
    policyEngine.addPolicy(
      address(vault),
      vault.withdraw.selector,
      address(pausePolicy),
      new bytes32[](0) // No parameters needed for
        // PausePolicy
    );

    vm.stopBroadcast();

    console.log("--- Deployed Contracts ---");
    console.log("MyVault deployed at:", address(vault));
    console.log("PolicyEngine deployed at:", address(policyEngine));
    console.log("PausePolicy deployed at:", address(pausePolicy));
  }
}
