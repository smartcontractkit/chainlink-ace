// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IPolicyEngine} from "../interfaces/IPolicyEngine.sol";
import {IPolicyProtected} from "../interfaces/IPolicyProtected.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {ERC165Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

/**
 * @title PolicyProtected.sol
 * @dev Base implementation for attaching a policy engine to a smart contract. Uses ERC-7201 storage
 *      to not conflict with other storage slots of extending contracts. Provides modifiers to be attached to methods
 *      of the extending contract to run the policy engine before executing the method.
 */
abstract contract PolicyProtected is Initializable, OwnableUpgradeable, ERC165Upgradeable, IPolicyProtected {
  /// @custom:storage-location erc7201:policy-management.PolicyProtected
  struct PolicyProtectedStorage {
    IPolicyEngine policyEngine;
    mapping(address sender => bytes context) senderContext; // use transient storage eventually
  }

  // keccak256(abi.encode(uint256(keccak256("policy-management.PolicyProtected")) - 1)) &
  // ~bytes32(uint256(0xff))
  // solhint-disable-next-line const-name-snakecase
  bytes32 private constant policyProtectedStorageLocation =
    0x381e6510830aa5d1f847c166134370760011d6c9becccc73371e64e18c3c4f00;

  function _policyProtectedStorage() private pure returns (PolicyProtectedStorage storage $) {
    // solhint-disable-next-line no-inline-assembly
    assembly {
      $.slot := policyProtectedStorageLocation
    }
  }

  constructor() {
    _disableInitializers();
  }

  function __PolicyProtected_init(address initialOwner, address policyEngine) internal onlyInitializing {
    __Ownable_init(initialOwner);
    __ERC165_init();
    __PolicyProtected_init_unchained(policyEngine);
  }

  function __PolicyProtected_init_unchained(address policyEngine) internal onlyInitializing {
    _attachPolicyEngine(policyEngine);
  }
  /**
   * @dev Modifier to run the policy engine on the current method.
   * @notice After the function execution completes, any context that was set will be automatically cleared.
   */

  modifier runPolicy() {
    if (address(_policyProtectedStorage().policyEngine) == address(0)) {
      revert IPolicyEngine.PolicyEngineUndefined();
    }
    bytes memory context = getContext();
    _policyProtectedStorage().policyEngine.run(
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
    if (address(_policyProtectedStorage().policyEngine) == address(0)) {
      revert IPolicyEngine.PolicyEngineUndefined();
    }
    _policyProtectedStorage().policyEngine.run(
      IPolicyEngine.Payload({selector: msg.sig, sender: msg.sender, data: msg.data[4:], context: context})
    );
    _;
  }

  /// @inheritdoc IPolicyProtected
  function attachPolicyEngine(address policyEngine) external virtual override onlyOwner {
    _attachPolicyEngine(policyEngine);
  }

  function _attachPolicyEngine(address policyEngine) internal {
    _policyProtectedStorage().policyEngine = IPolicyEngine(policyEngine);
    IPolicyEngine(policyEngine).attach();
    emit PolicyEngineAttached(policyEngine);
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
