// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {PolicyProtectedBase} from "./PolicyProtectedBase.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title PolicyProtected.sol
 * @dev Abstract contract for an ACE-protected smart contract This version uses the OpenZeppelin Ownable module for
 * authorization.
 */
abstract contract PolicyProtected is Ownable, PolicyProtectedBase {
  constructor(address initialOwner, address policyEngine) Ownable(initialOwner) PolicyProtectedBase(policyEngine) {}

  function _authorizeAttachPolicyEngine(address) internal virtual override onlyOwner {}
}
