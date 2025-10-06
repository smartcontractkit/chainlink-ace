// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ComplianceTokenERC3643} from "../packages/tokens/erc-3643/src/ComplianceTokenERC3643.sol";
import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

contract DeploySimpleComplianceToken is Script {
  function run() external {
    uint256 tokenOwnerPK = vm.envUint("PRIVATE_KEY");
    address tokenOwner = vm.addr(tokenOwnerPK);

    vm.startBroadcast(tokenOwnerPK);

    // Deploy the ComplianceToken through proxy
    ComplianceTokenERC3643 tokenImpl = new ComplianceTokenERC3643();
    bytes memory tokenData = abi.encodeWithSelector(
      ComplianceTokenERC3643.initialize.selector,
      vm.envOr("TOKEN_NAME", string("Token")),
      vm.envOr("TOKEN_SYMBOL", string("TOKEN")),
      18,
      vm.envAddress("POLICY_ENGINE")
    );
    ERC1967Proxy tokenProxy = new ERC1967Proxy(address(tokenImpl), tokenData);
    ComplianceTokenERC3643 token = ComplianceTokenERC3643(address(tokenProxy));

    uint256 initialSupply = vm.envOr("INITIAL_SUPPLY", uint256(1000000));
    address initialHolder = vm.envOr("INITIAL_HOLDER", address(0));
    if (initialHolder != address(0)) {
      token.mint(initialHolder, initialSupply * 10 ** token.decimals());
    }

    vm.stopBroadcast();

    console.log("ComplianceToken deployed at:", address(token));
  }
}
