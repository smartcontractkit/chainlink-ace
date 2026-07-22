// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IPolicyEngine} from "../interfaces/IPolicyEngine.sol";
import {IPolicyProtected} from "../interfaces/IPolicyProtected.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {ERC165Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";

/**
 * @title PolicyProtectedBaseUpgradeable.sol
 * @dev Base implementation for attaching a policy engine to an upgradeable smart contract. Uses ERC-7201 storage
 *      to not conflict with other storage slots of extending contracts. Provides modifiers to be attached to methods
 *      of the extending contract to run the policy engine before executing the method.
 */
abstract contract PolicyProtectedBaseUpgradeable is ERC165Upgradeable, IPolicyProtected {
  /// @custom:storage-location erc7201:chainlink.ace.PolicyProtected
  struct PolicyProtectedStorage {
    IPolicyEngine policyEngine;
    mapping(address sender => bytes context) senderContext; // use transient storage eventually
  }

  // keccak256(abi.encode(uint256(keccak256("chainlink.ace.PolicyProtected")) - 1)) &
  // ~bytes32(uint256(0xff))
  // solhint-disable-next-line const-name-snakecase
  bytes32 private constant policyProtectedStorageLocation =
    0x5970a53874f73819f13c80052b0c1b19d6ce68b29b2ad28a7413019c8a409000;

  function _policyProtectedStorage() private pure returns (PolicyProtectedStorage storage $) {
    // solhint-disable-next-line no-inline-assembly
    assembly {
      $.slot := policyProtectedStorageLocation
    }
  }

  function __PolicyProtectedBase_init(address policyEngine) internal onlyInitializing {
    __ERC165_init();
    __PolicyProtectedBase_init_unchained(policyEngine);
  }

  function __PolicyProtectedBase_init_unchained(address policyEngine) internal onlyInitializing {
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
    if (address(_policyProtectedStorage().policyEngine) == address(0)) {
      revert IPolicyEngine.PolicyEngineUndefined();
    }
    bytes memory context = getContext();
    _policyProtectedStorage().policyEngine
      .run(IPolicyEngine.Payload({selector: msg.sig, sender: msg.sender, data: msg.data[4:], context: context}));
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
    if (address(_policyProtectedStorage().policyEngine) == address(0)) {
      revert IPolicyEngine.PolicyEngineUndefined();
    }
    _policyProtectedStorage().policyEngine
      .run(IPolicyEngine.Payload({selector: msg.sig, sender: msg.sender, data: msg.data[4:], context: context}));
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

  function _attachPolicyEngine(address policyEngine) internal {
    IPolicyEngine oldEngine = _policyProtectedStorage().policyEngine;
    _policyProtectedStorage().policyEngine = IPolicyEngine(policyEngine);
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
    return address(_policyProtectedStorage().policyEngine);
  }

  /// @inheritdoc IPolicyProtected
  function setContext(bytes calldata context) public override {
    _policyProtectedStorage().senderContext[msg.sender] = context;
  }

  /// @inheritdoc IPolicyProtected
  function getContext() public view override returns (bytes memory) {
    return _policyProtectedStorage().senderContext[msg.sender];
  }

  /// @inheritdoc IPolicyProtected
  function getSenderContext(address sender) public view override returns (bytes memory) {
    return _policyProtectedStorage().senderContext[sender];
  }

  /// @inheritdoc IPolicyProtected
  function clearContext() public override {
    delete _policyProtectedStorage().senderContext[msg.sender];
  }

  /**
   * @dev See {IERC165-supportsInterface}.
   */
  function supportsInterface(bytes4 interfaceId)
    public
    view
    virtual
    override(ERC165Upgradeable, IERC165)
    returns (bool)
  {
    return interfaceId == type(IPolicyProtected).interfaceId || super.supportsInterface(interfaceId);
  }
}
