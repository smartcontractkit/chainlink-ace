// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IPolicyEngine} from "../interfaces/IPolicyEngine.sol";
import {IPolicyProtected} from "../interfaces/IPolicyProtected.sol";
import {IERC165, ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title PolicyProtected.sol
 * @dev Base implementation for attaching a policy engine to a smart contract. Provides modifiers to be attached
 *      to methods of the extending contract to run the policy engine before executing the method.
 */
abstract contract PolicyProtected is Ownable, ERC165, IPolicyProtected {
  IPolicyEngine internal s_policyEngine;
  mapping(address sender => bytes context) internal s_senderContext; // use transient storage eventually

  constructor(address initialOwner, address policyEngine) Ownable(initialOwner) {
    _attachPolicyEngine(policyEngine);
  }

  /**
   * @dev Modifier to run the policy engine on the current method.
   * @notice After the function execution completes, any context that was set will be automatically cleared.
   */
  modifier runPolicy() {
    if (address(s_policyEngine) == address(0)) {
      revert IPolicyEngine.PolicyEngineUndefined();
    }
    bytes memory context = getContext();
    s_policyEngine.run(
      IPolicyEngine.Payload({selector: msg.sig, sender: msg.sender, data: msg.data[4:], context: context})
    );
    _;
    if (context.length > 0) {
      clearContext();
    }
  }

  /**
   * @dev Modifier to run the policy engine on the current method with the provided context.
   * @param context Additional information or authorization to perform the operation.
   */
  modifier runPolicyWithContext(bytes calldata context) {
    if (address(s_policyEngine) == address(0)) {
      revert IPolicyEngine.PolicyEngineUndefined();
    }
    s_policyEngine.run(
      IPolicyEngine.Payload({selector: msg.sig, sender: msg.sender, data: msg.data[4:], context: context})
    );
    _;
  }

  /// @inheritdoc IPolicyProtected
  function attachPolicyEngine(address policyEngine) external virtual override onlyOwner {
    _attachPolicyEngine(policyEngine);
  }

  function _attachPolicyEngine(address policyEngine) internal {
    require(policyEngine != address(0), "Policy engine is zero address");
    if (address(s_policyEngine) != address(0)) {
      try s_policyEngine.detach() {
        // Detachment succeeded
      } catch (bytes memory reason) {
        emit PolicyEngineDetachFailed(address(s_policyEngine), reason);
      }
    }
    s_policyEngine = IPolicyEngine(policyEngine);
    s_policyEngine.attach();
    emit PolicyEngineAttached(policyEngine);
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
