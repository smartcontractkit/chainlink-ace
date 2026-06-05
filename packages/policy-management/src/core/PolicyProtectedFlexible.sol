// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IPolicyEngine} from "../interfaces/IPolicyEngine.sol";
import {PolicyProtectedBase} from "./PolicyProtectedBase.sol";

/**
 * @title PolicyProtectedFlexible.sol
 * @dev A flexible version of PolicyProtectedBase that does not require a PolicyEngine be attached at
 *      deployment time and a PolicyEngine can be attached later via attachPolicyEngine(), with the implementing
 *      class responsible for implementing the _authorizeAttachPolicyEngine() method to enforce access control over
 *      attaching a PolicyEngine.
 */
abstract contract PolicyProtectedFlexible is PolicyProtectedBase {
  constructor(address policyEngine) PolicyProtectedBase(policyEngine) {}

  /**
   * @dev allow policyEngine to not be set - in that case execute without any policy enforcement
   */
  function _runPolicyBefore() internal virtual override {
    address policyEngineAddress = getPolicyEngine();
    bytes memory context = getContext();
    if (policyEngineAddress != address(0)) {
      IPolicyEngine(policyEngineAddress)
        .run(IPolicyEngine.Payload({selector: msg.sig, sender: msg.sender, data: msg.data[4:], context: context}));
    }
  }

  /**
   * @dev Modifier to run the policy engine (if one is attached) on the current method with the provided context.
   * @param context Additional information or authorization to perform the operation.
   */
  modifier runPolicyWithContext(bytes calldata context) override {
    address policyEngineAddress = getPolicyEngine();
    if (policyEngineAddress != address(0)) {
      IPolicyEngine(policyEngineAddress)
        .run(IPolicyEngine.Payload({selector: msg.sig, sender: msg.sender, data: msg.data[4:], context: context}));
    }
    _;
  }

  /**
   * @dev Override base version to allow a policyEngine of address(0)
   */
  // solhint-disable-next-line no-empty-blocks
  function _validatePolicyEngine(address policyEngine) internal virtual override {}
}
