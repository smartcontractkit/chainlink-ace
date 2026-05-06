// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {ICertifiedActionValidator} from "../interfaces/ICertifiedActionValidator.sol";

/**
 * @title CertifiedActionLib
 * @notice Library containing common constants and functions for Permit handling
 */
library CertifiedActionLib {
  // EIP-712 type strings and hashes for consistent structured data signing
  string internal constant PERMIT_TYPE = "Permit(bytes32 permitId,address caller,address subject,bytes4 selector,"
    "bytes[] parameters,bytes metadata,uint64 maxUses,uint48 expiry)";
  bytes32 internal constant PERMIT_TYPEHASH = keccak256(abi.encodePacked(PERMIT_TYPE));

  /**
   * @notice Hashes a Permit using EIP-712.
   * @param permit The Permit to hash.
   * @return hash hash of the Permit.
   */
  function _hashPermit(ICertifiedActionValidator.Permit memory permit) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        PERMIT_TYPEHASH,
        permit.permitId,
        permit.caller,
        permit.subject,
        permit.selector,
        _hashPermitParameters(permit.parameters),
        keccak256(permit.metadata),
        permit.maxUses,
        permit.expiry
      )
    );
  }

  function _hashPermitParameters(bytes[] memory parameters) internal pure returns (bytes32) {
    // EIP-712 defines the encoding for bytes arrays as:
    // keccak256( keccak256(encodeData(value[0])) ‖ keccak256(encodeData(value[1])) ‖ … ‖
    //            keccak256(encodeData(value[n])) )
    bytes32[] memory hashes = new bytes32[](parameters.length);
    for (uint256 i = 0; i < parameters.length; i++) {
      hashes[i] = keccak256(parameters[i]);
    }
    return keccak256(abi.encodePacked(hashes));
  }
}
