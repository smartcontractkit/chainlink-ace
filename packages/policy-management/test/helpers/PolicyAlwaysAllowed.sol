// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IPolicyEngine} from "../../src/interfaces/IPolicyEngine.sol";
import {Policy} from "../../src/core/Policy.sol";

contract PolicyAlwaysAllowed is Policy {
  uint8 private s_policyNumber;

  event PolicyAllowedExecuted(uint256 value);

  function configure(bytes calldata parameters) internal override onlyInitializing {
    uint8 policyNumber = abi.decode(parameters, (uint8));
    s_policyNumber = policyNumber;
  }

  function getPolicyNumber() public view returns (uint8) {
    return s_policyNumber;
  }

  function run(
    address,
    address,
    bytes4,
    bytes[] calldata,
    bytes calldata
  )
    public
    pure
    override
    returns (IPolicyEngine.PolicyResult)
  {
    return IPolicyEngine.PolicyResult.Allowed;
  }

  function postRun(address, address, bytes4, bytes[] calldata, bytes calldata) public virtual override {
    emit PolicyAllowedExecuted(s_policyNumber);
  }
}

contract PolicyAlwaysAllowedWithPostRunError is PolicyAlwaysAllowed {
  function postRun(address, address, bytes4, bytes[] calldata, bytes calldata) public pure override {
    revert("Post run error");
  }
}
