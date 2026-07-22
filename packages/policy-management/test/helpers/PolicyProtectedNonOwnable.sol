// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IPolicyEngine} from "../../src/interfaces/IPolicyEngine.sol";
import {IPolicyProtected} from "../../src/interfaces/IPolicyProtected.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

contract PolicyProtectedNonOwnable is IPolicyProtected {
  IPolicyEngine private _policyEngine;

  constructor(address policyEngine) {
    _attachPolicyEngine(policyEngine);
  }

  function protectedFunction() external {
    _policyEngine.run(IPolicyEngine.Payload({selector: msg.sig, sender: msg.sender, data: msg.data[4:], context: ""}));
  }

  function _attachPolicyEngine(address policyEngine) internal {
    _policyEngine = IPolicyEngine(policyEngine);
    _policyEngine.attach();
  }

  function attachPolicyEngine(address policyEngine) external override {
    _attachPolicyEngine(policyEngine);
  }

  function getPolicyEngine() external view override returns (address) {
    return address(_policyEngine);
  }

  function setContext(bytes calldata) external override {}

  function getContext() external pure override returns (bytes memory) {
    return "";
  }

  function getSenderContext(address) external pure override returns (bytes memory) {
    return "";
  }

  function clearContext() external override {}

  function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
    return interfaceId == type(IPolicyProtected).interfaceId || interfaceId == type(IERC165).interfaceId;
  }
}
