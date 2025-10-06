// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {CredentialRegistryIdentityValidator} from "./CredentialRegistryIdentityValidator.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {Policy} from "@chainlink/policy-management/core/Policy.sol";
import {ICredentialRequirements} from "@chainlink/cross-chain-identity/interfaces/ICredentialRequirements.sol";

contract CredentialRegistryIdentityValidatorPolicy is Policy, CredentialRegistryIdentityValidator {
  /**
   * @notice Configures the policy by setting up credential sources and credential requirements.
   * @dev The `parameters` input must be the ABI encoding of two dynamic arrays:
   * - An array of `CredentialSourceInput` structs (credential sources).
   * - An array of `CredentialRequirementInput` structs (credential requirements).
   *
   * The function expects the parameters to be tightly packed together, meaning that the entire calldata
   * should decode as `(CredentialSourceInput[], CredentialRequirementInput[])`.
   *
   * @param parameters ABI-encoded bytes containing two arrays: one of `CredentialSourceInput` and one of
   * `CredentialRequirementInput`.
   */
  function configure(bytes calldata parameters) internal override onlyInitializing {
    if (parameters.length == 0) {
      __CredentialRegistryIdentitityValidator_init_unchained(
        new ICredentialRequirements.CredentialSourceInput[](0),
        new ICredentialRequirements.CredentialRequirementInput[](0)
      );
      return;
    }

    (
      ICredentialRequirements.CredentialSourceInput[] memory credentialSourceInputs,
      ICredentialRequirements.CredentialRequirementInput[] memory credentialRequirementInputs
    ) = abi.decode(
      parameters,
      (ICredentialRequirements.CredentialSourceInput[], ICredentialRequirements.CredentialRequirementInput[])
    );
    // We call the init_unchained_() method to avoid calling _Ownable__init_() twice (Policy has called it before
    // invoking configure), likely changing the owner (Policy uses the initialOwner param and IdentityValidator the
    // msg.sender global variable).
    __CredentialRegistryIdentitityValidator_init_unchained(credentialSourceInputs, credentialRequirementInputs);
  }

  function run(
    address, /*caller*/
    address, /*subject*/
    bytes4, /*selector*/
    bytes[] calldata parameters,
    bytes calldata context
  )
    public
    view
    override
    returns (IPolicyEngine.PolicyResult)
  {
    // expected parameters: [account(address)]
    if (parameters.length != 1) {
      revert IPolicyEngine.InvalidConfiguration("expected 1 parameter");
    }
    address account = abi.decode(parameters[0], (address));

    if (!validate(account, context)) {
      return IPolicyEngine.PolicyResult.Rejected;
    }
    return IPolicyEngine.PolicyResult.Continue;
  }

  function supportsInterface(bytes4 interfaceId) public view override(Policy) returns (bool) {
    return super.supportsInterface(interfaceId);
  }
}
