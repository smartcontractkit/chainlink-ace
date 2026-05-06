// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {ICertifiedActionValidator} from "../../src/interfaces/ICertifiedActionValidator.sol";
import {CertifiedActionValidatorPolicy} from "../../src/policies/CertifiedActionValidatorPolicy.sol";
import {BaseProxyTest} from "./BaseProxyTest.sol";

contract BaseCertifiedActionTest is BaseProxyTest {
  uint256 private _nonce;

  function _generatePermit(
    address caller,
    address subject,
    bytes4 selector,
    bytes[] memory parameters
  )
    internal
    returns (ICertifiedActionValidator.Permit memory)
  {
    return ICertifiedActionValidator.Permit(
      keccak256(abi.encodePacked(_nonce++)),
      caller,
      address(subject),
      selector,
      parameters,
      "",
      0,
      uint48(block.timestamp + 1 days)
    );
  }

  function _signPermit(
    CertifiedActionValidatorPolicy policy,
    ICertifiedActionValidator.Permit memory permit,
    uint256 pKey
  )
    internal
    view
    returns (bytes memory)
  {
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(pKey, policy.hashTypedDataV4Permit(permit));
    return abi.encodePacked(r, s, v);
  }
}
