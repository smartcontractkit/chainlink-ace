// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IPolicyProtected} from "../interfaces/IPolicyProtected.sol";
import {PolicyProtectedBaseUpgradeable} from "./PolicyProtectedBaseUpgradeable.sol";
import {ERC165Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

/**
 * @title PolicyProtectedUpgradeable.sol
 * @dev Abstract contract for an ACE-protected smart contract This version uses the OpenZeppelin upgrade-compatible
 * OwnableUpgradeable for authorization.
 */
abstract contract PolicyProtectedUpgradeable is ERC165Upgradeable, OwnableUpgradeable, PolicyProtectedBaseUpgradeable {
  function __PolicyProtected_init(address initialOwner, address policyEngine) internal onlyInitializing {
    __ERC165_init();
    __Ownable_init(initialOwner);
    __PolicyProtected_init_unchained(policyEngine);
  }

  function __PolicyProtected_init_unchained(address policyEngine) internal onlyInitializing {
    __PolicyProtectedBase_init_unchained(policyEngine);
  }

  function _authorizeAttachPolicyEngine(address) internal virtual override onlyOwner {}

  /**
   * @dev See {IERC165-supportsInterface}.
   */
  function supportsInterface(bytes4 interfaceId)
    public
    view
    virtual
    override(PolicyProtectedBaseUpgradeable, ERC165Upgradeable)
    returns (bool)
  {
    return interfaceId == type(IPolicyProtected).interfaceId || super.supportsInterface(interfaceId);
  }
}
