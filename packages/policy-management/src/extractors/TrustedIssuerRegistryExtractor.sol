// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IExtractor} from "../interfaces/IExtractor.sol";
import {IPolicyEngine} from "../interfaces/IPolicyEngine.sol";
import {ITrustedIssuerRegistry} from "../../../cross-chain-identity/src/interfaces/ITrustedIssuerRegistry.sol";

/**
 * @title TrustedIssuerRegistryExtractor
 * @notice Extracts parameters from ITrustedIssuerRegistry administrative function calls.
 * @dev Supports addTrustedIssuer and removeTrustedIssuer.
 */
contract TrustedIssuerRegistryExtractor is IExtractor {
  /// @notice Type and version of the extractor
  string public constant override typeAndVersion = "TrustedIssuerRegistryExtractor 1.2.0";

  /// @notice Parameter key for the issuer identifier string
  bytes32 public constant PARAM_ISSUER_ID = keccak256("issuerId");

  /**
   * @inheritdoc IExtractor
   * @dev Extracts issuerId from ITrustedIssuerRegistry admin calls.
   *      - addTrustedIssuer(string,bytes): issuerId decoded
   *      - removeTrustedIssuer(string,bytes): issuerId decoded
   */
  function extract(IPolicyEngine.Payload calldata payload)
    external
    pure
    override
    returns (IPolicyEngine.Parameter[] memory)
  {
    string memory issuerId;

    if (
      payload.selector == ITrustedIssuerRegistry.addTrustedIssuer.selector
        || payload.selector == ITrustedIssuerRegistry.removeTrustedIssuer.selector
    ) {
      (issuerId,) = abi.decode(payload.data, (string, bytes));
    } else {
      revert IPolicyEngine.UnsupportedSelector(payload.selector);
    }

    IPolicyEngine.Parameter[] memory result = new IPolicyEngine.Parameter[](1);
    result[0] = IPolicyEngine.Parameter(PARAM_ISSUER_ID, abi.encode(issuerId));
    return result;
  }
}
