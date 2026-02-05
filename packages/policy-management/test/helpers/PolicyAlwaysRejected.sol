// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.20;

import {IPolicyEngine} from "../../src/interfaces/IPolicyEngine.sol";
import {Policy} from "../../src/core/Policy.sol";

contract PolicyAlwaysRejected is Policy {
  string public constant override typeAndVersion = "PolicyAlwaysRejected 1.0.0";

  event ConfigFuncExecuted();

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
    revert IPolicyEngine.PolicyRejected("test policy always rejects");
  }

  function configFunc() external onlyOwner {
    // dummy logic
    emit ConfigFuncExecuted();
  }
}
