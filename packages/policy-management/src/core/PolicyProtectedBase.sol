// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IPolicyEngine} from "../interfaces/IPolicyEngine.sol";
import {IPolicyProtected} from "../interfaces/IPolicyProtected.sol";
import {IERC165, ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";

/**
 * @title PolicyProtectedBase.sol
 * @dev Base implementation for attaching a policy engine to a smart contract. Provides modifiers to be attached
 *      to methods of the extending contract to run the policy engine before executing the method.
 */
abstract contract PolicyProtectedBase is ERC165, IPolicyProtected {
  IPolicyEngine internal s_policyEngine;
  mapping(address sender => bytes context) internal s_senderContext; // use transient storage eventually

  constructor(address policyEngine) {
    _validatePolicyEngine(policyEngine);
    _attachPolicyEngine(policyEngine);
  }

  /**
   * @dev Modifier to run the policy engine on the current method.
   * @notice After the function execution completes, any context that was set will be automatically cleared.
   */
  modifier runPolicy() {
    _runPolicyBefore();
    _;
    _runPolicyAfter();
  }

  function _runPolicyBefore() internal virtual {
    if (address(s_policyEngine) == address(0)) {
      revert IPolicyEngine.PolicyEngineUndefined();
    }
    bytes memory context = getContext();
    s_policyEngine.run(
      IPolicyEngine.Payload({selector: msg.sig, sender: msg.sender, data: msg.data[4:], context: context})
    );
  }

  function _runPolicyAfter() internal virtual {
    if (getContext().length > 0) {
      clearContext();
    }
  }

  /**
   * @dev Modifier to run the policy engine on the current method with the provided context.
   * @param context Additional information or authorization to perform the operation.
   */
  modifier runPolicyWithContext(bytes calldata context) virtual {
    if (address(s_policyEngine) == address(0)) {
      revert IPolicyEngine.PolicyEngineUndefined();
    }
    s_policyEngine.run(
      IPolicyEngine.Payload({selector: msg.sig, sender: msg.sender, data: msg.data[4:], context: context})
    );
    _;
  }

  function _validatePolicyEngine(address policyEngine) internal virtual {
    require(policyEngine != address(0), "Policy engine is zero address");
  }

  function _authorizeAttachPolicyEngine(address policyEngine) internal virtual;

  /// @inheritdoc IPolicyProtected
  function attachPolicyEngine(address policyEngine) external virtual override {
    _authorizeAttachPolicyEngine(policyEngine);
    _validatePolicyEngine(policyEngine);
    _attachPolicyEngine(policyEngine);
  }

  /**
   * @dev Points this contract at `policyEngine`, attaches to it, then best-effort detaches from the previous engine.
   *      A policy engine's `detach()` is expected never to revert. If the old engine's `detach()` does revert, the
   *      failure is swallowed (only `PolicyEngineDetachFailed` is emitted) so that engine rotation still succeeds.
   *      The consequence is that the old engine keeps recording this contract as attached, so a later attempt to
   *      re-attach that same engine will revert with `TargetAlreadyAttached`. This is acceptable because a reverting
   *      `detach()` only occurs with a malfunctioning engine; recovering re-attachment to such an engine would require
   *      an out-of-band fix on the engine side.
   */
  function _attachPolicyEngine(address policyEngine) internal {
    IPolicyEngine oldEngine = s_policyEngine;
    s_policyEngine = IPolicyEngine(policyEngine);
    if (policyEngine != address(0)) {
      IPolicyEngine(policyEngine).attach();
      emit PolicyEngineAttached(policyEngine);
    }
    if (address(oldEngine) != address(0)) {
      try oldEngine.detach() {
      // Detachment succeeded
      }
      catch (bytes memory reason) {
        emit PolicyEngineDetachFailed(address(oldEngine), reason);
      }
    }
  }

  /// @inheritdoc IPolicyProtected
  function getPolicyEngine() public view virtual override returns (address) {
    return address(s_policyEngine);
  }

  /// @inheritdoc IPolicyProtected
  function setContext(bytes calldata context) public override {
    s_senderContext[msg.sender] = context;
  }

  /// @inheritdoc IPolicyProtected
  function getContext() public view override returns (bytes memory) {
    return s_senderContext[msg.sender];
  }

  /// @inheritdoc IPolicyProtected
  function getSenderContext(address sender) public view override returns (bytes memory) {
    return s_senderContext[sender];
  }

  /// @inheritdoc IPolicyProtected
  function clearContext() public override {
    delete s_senderContext[msg.sender];
  }

  /**
   * @dev See {IERC165-supportsInterface}.
   */
  function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
    return interfaceId == type(IPolicyProtected).interfaceId || super.supportsInterface(interfaceId);
  }
}
