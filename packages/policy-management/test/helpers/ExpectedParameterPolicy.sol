// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IPolicyEngine} from "../../src/interfaces/IPolicyEngine.sol";
import {Policy} from "../../src/core/Policy.sol";

contract ExpectedParameterPolicy is Policy {
  bytes[] private s_expectedParameters;

  function configure(bytes calldata parameters) internal override onlyInitializing {
    bytes[] memory expectedParameters = abi.decode(parameters, (bytes[]));
    s_expectedParameters = expectedParameters;
  }

  function setExpectedParameters(bytes[] memory expectedParameters) public onlyOwner {
    s_expectedParameters = expectedParameters;
  }

  function run(
    address, /*caller*/
    address, /*subject*/
    bytes4, /*selector*/
    bytes[] calldata parameters,
    bytes calldata /*context*/
  )
    public
    view
    override
    returns (IPolicyEngine.PolicyResult)
  {
    if (
      parameters.length == s_expectedParameters.length
        && keccak256(abi.encode(parameters)) == keccak256(abi.encode(s_expectedParameters))
    ) {
      return IPolicyEngine.PolicyResult.Allowed;
    }
    return IPolicyEngine.PolicyResult.Rejected;
  }
}
