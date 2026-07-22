// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {CredentialRegistryIdentityValidator} from "./CredentialRegistryIdentityValidator.sol";
import {ICredentialDataValidator} from "./interfaces/ICredentialDataValidator.sol";
import {ICredentialRegistry} from "./interfaces/ICredentialRegistry.sol";
import {ICredentialRequirements} from "./interfaces/ICredentialRequirements.sol";
import {IIdentityRegistry} from "./interfaces/IIdentityRegistry.sol";
import {IIdentityValidator} from "./interfaces/IIdentityValidator.sol";
import {IPolicyEngine} from "../../policy-management/src/interfaces/IPolicyEngine.sol";
import {Policy} from "../../policy-management/src/core/Policy.sol";

contract CredentialRegistryIdentityValidatorPolicy is Policy, CredentialRegistryIdentityValidator {
  string public constant override typeAndVersion = "CredentialRegistryIdentityValidatorPolicy 1.2.0";

  /**
   * @notice Authorize the following configuration functions:
   * - addCredentialRequirement
   * - removeCredentialRequirement
   * - addCredentialSource
   *  -removeCredentialSource
   */
  function authorizeConfigSelector(bytes4 selector) public pure override returns (bool) {
    return (selector == this.addCredentialRequirement.selector || selector == this.removeCredentialRequirement.selector
        || selector == this.addCredentialSource.selector || selector == this.removeCredentialSource.selector);
  }

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
      __CredentialRegistryIdentityValidator_init_unchained(
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
    __CredentialRegistryIdentityValidator_init_unchained(credentialSourceInputs, credentialRequirementInputs);
  }

  /**
   * @notice Function to be called by the policy engine to check if execution is allowed.
   * @param parameters Encoded policy parameters.
   *        [account(address),...] List of accounts to validate.
   * @param context Encoded policy context passed through to credential and data validation.
   * @return result Continue when every account satisfies the configured credential requirements.
   */
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
    if (parameters.length < 1) {
      revert InvalidParameters("expected at least 1 parameter");
    }

    for (uint256 i = 0; i < parameters.length; i++) {
      address account = abi.decode(parameters[i], (address));
      if (!validate(account, context)) {
        revert IPolicyEngine.PolicyRejected("account identity validation failed");
      }
    }
    return IPolicyEngine.PolicyResult.Continue;
  }

  /**
   * @notice Runs after successful policy checks and emits identity validation events for each account.
   * @param parameters Encoded policy parameters.
   *        [account(address),...] List of accounts to emit validation events for.
   * @param context Encoded policy context passed through to credential and data validation.
   */
  function postRun(
    address, /*caller*/
    address, /*subject*/
    bytes4, /*selector*/
    bytes[] calldata parameters,
    bytes calldata context
  )
    public
    override
    onlyPolicyEngine
  {
    for (uint256 i = 0; i < parameters.length; i++) {
      address account = abi.decode(parameters[i], (address));
      _emitIdentityValidatedForAccount(account, context);
    }
  }

  /**
   * @notice Emits identity validation events for all requirements satisfied by an account.
   * @param account Account whose identity validation should be emitted.
   * @param context Encoded policy context passed through to credential and data validation.
   */
  function _emitIdentityValidatedForAccount(address account, bytes calldata context) internal {
    if (!validate(account, context)) {
      return;
    }

    bytes32[] memory requirementIds = getCredentialRequirementIds();
    for (uint256 i = 0; i < requirementIds.length; i++) {
      if (!_emitForRequirement(account, requirementIds[i], context)) {
        return;
      }
    }
  }

  /**
   * @notice Emits identity validation events for a satisfied credential requirement.
   * @param account Account whose requirement validation should be emitted.
   * @param requirementId Requirement identifier to emit for.
   * @param context Encoded policy context passed through to credential and data validation.
   * @return emitted True when the requirement had enough valid credentials to emit.
   */
  function _emitForRequirement(address account, bytes32 requirementId, bytes calldata context) internal returns (bool) {
    ICredentialRequirements.CredentialRequirement memory requirement = getCredentialRequirement(requirementId);
    uint256 validations = 0;

    for (uint256 i = 0; i < requirement.credentialTypeIds.length; i++) {
      bytes32 credentialTypeId = requirement.credentialTypeIds[i];
      ICredentialRequirements.CredentialSource[] memory sources = getCredentialSources(credentialTypeId);

      for (uint256 j = 0; j < sources.length; j++) {
        (bool valid, bytes32 ccid, bytes memory credentialData) =
          _sourceSatisfiesCredential(account, sources[j], credentialTypeId, requirement.invert, context);
        if (!valid) {
          continue;
        }

        _emitIdentityValidated(account, ccid, credentialTypeId, sources[j], credentialData);
        validations++;
        if (validations >= requirement.minValidations) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * @notice Resolves identity and credential data for a source credential validation.
   * @param account Account to validate.
   * @param source Credential source to validate.
   * @param credentialTypeId Credential type identifier to validate.
   * @param invert Whether the credential requirement is inverted.
   * @param context Encoded policy context passed through to credential and data validation.
   * @return valid True when the source satisfies the credential validation.
   * @return ccid Cross-chain identity resolved for the account.
   * @return credentialData Credential data used by a configured data validator.
   */
  function _sourceSatisfiesCredential(
    address account,
    ICredentialRequirements.CredentialSource memory source,
    bytes32 credentialTypeId,
    bool invert,
    bytes calldata context
  )
    internal
    view
    returns (bool, bytes32, bytes memory)
  {
    bytes32 ccid;
    try IIdentityRegistry(source.identityRegistry).getIdentity(account) returns (bytes32 resolvedCCID) {
      ccid = resolvedCCID;
    } catch {
      return (false, bytes32(0), "");
    }

    if (ccid == bytes32(0)) {
      // Mirror the base validator, which counts a missing identity as satisfying an inverted requirement. The emit
      // path must report this requirement as satisfied (with no resolved CCID) so its IdentityValidated event - and
      // those of every later requirement - are not silently dropped for an authorised, identity-less account.
      return (invert, bytes32(0), "");
    }

    bool credentialExists;
    try ICredentialRegistry(source.credentialRegistry).validate(ccid, credentialTypeId, context) returns (bool valid) {
      credentialExists = valid;
    } catch {
      return (false, ccid, "");
    }

    if (invert) {
      return (!credentialExists, ccid, "");
    }

    if (!credentialExists) {
      return (false, ccid, "");
    }

    bytes memory credentialData;
    if (source.dataValidator != address(0)) {
      try ICredentialRegistry(source.credentialRegistry).getCredential(ccid, credentialTypeId) returns (
        ICredentialRegistry.Credential memory credential
      ) {
        credentialData = credential.credentialData;
      } catch {
        return (false, ccid, "");
      }

      try ICredentialDataValidator(source.dataValidator)
        .validateCredentialData(ccid, account, credentialTypeId, credentialData, context) returns (
        bool dataValid
      ) {
        if (!dataValid) {
          return (false, ccid, "");
        }
      } catch {
        return (false, ccid, "");
      }
    }

    return (true, ccid, credentialData);
  }

  /**
   * @notice Emits a single identity validation event.
   * @param account Account whose identity was validated.
   * @param ccid Cross-chain identity resolved for the account.
   * @param credentialTypeId Credential type that satisfied validation.
   * @param source Credential source that provided the validation.
   * @param credentialData Credential data used to compute the emitted hash when a data validator is configured.
   */
  function _emitIdentityValidated(
    address account,
    bytes32 ccid,
    bytes32 credentialTypeId,
    ICredentialRequirements.CredentialSource memory source,
    bytes memory credentialData
  )
    internal
  {
    emit IdentityValidated(
      account,
      ccid,
      credentialTypeId,
      source.credentialRegistry,
      source.dataValidator,
      _credentialDataHash(source.dataValidator, credentialData)
    );
  }

  /**
   * @notice Computes the credential data hash emitted with identity validation events.
   * @param dataValidator Data validator configured for the credential source, if any.
   * @param credentialData Credential data to hash.
   * @return credentialDataHash Hash of credential data, or zero when no data validator is configured.
   */
  function _credentialDataHash(address dataValidator, bytes memory credentialData) internal pure returns (bytes32) {
    if (dataValidator == address(0)) {
      return bytes32(0);
    }
    return keccak256(credentialData);
  }

  /**
   * @notice Checks whether this contract implements an interface.
   * @param interfaceId Interface identifier to check.
   * @return supported True when the interface is supported.
   */
  function supportsInterface(bytes4 interfaceId) public view override(Policy) returns (bool) {
    return interfaceId == type(IIdentityValidator).interfaceId || super.supportsInterface(interfaceId);
  }
}
