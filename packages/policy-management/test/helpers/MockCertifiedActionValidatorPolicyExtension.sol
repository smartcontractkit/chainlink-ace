// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {CertifiedActionValidatorPolicy} from "../../src/policies/CertifiedActionValidatorPolicy.sol";

contract MockCertifiedActionValidatorPolicyExtension is CertifiedActionValidatorPolicy {
  function _validatePrePresentedPermitHook(
    bytes32, /*permitId*/
    address, /*caller*/
    address, /*subject*/
    bytes4, /*selector*/
    bytes[] memory /*parameters*/
  )
    internal
    view
    override
    returns (bool)
  {
    // call a non-internal function so that it is observable by vm.expectCall
    return this.validatePrePresentedPermitHook();
  }

  function validatePrePresentedPermitHook() public pure returns (bool) {
    return true;
  }

  function _validateSignedPermitHook(
    Permit memory, /*permit*/
    address, /*caller*/
    address, /*subject*/
    bytes4, /*selector*/
    bytes[] memory /*parameters*/
  )
    internal
    view
    override
    returns (bool)
  {
    // call a non-internal function so that it is observable by vm.expectCall
    return this.validatePermitHook();
  }

  function validatePermitHook() public pure returns (bool) {
    return true;
  }
}
