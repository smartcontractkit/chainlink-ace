// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {SanctionsList} from "../../../getting_started/advanced/SanctionsList.sol";

/**
 * @title DeploySanctionsList (Part of the Advanced Getting Started Guide)
 * @notice Deployment script for the Sanctions Provider to deploy their independent SanctionsList.
 * @dev This script is run by the Sanctions Provider using their own private key.
 *      The deployed address is then used by the Fund Manager's compliance system.
 */
contract DeploySanctionsList is Script {
  function run() external {
    uint256 deployerPK = vm.envUint("PRIVATE_KEY");

    vm.startBroadcast(deployerPK);

    SanctionsList sanctionsList = new SanctionsList();

    vm.stopBroadcast();

    console.log("SanctionsList deployed at:", address(sanctionsList));
  }
}
