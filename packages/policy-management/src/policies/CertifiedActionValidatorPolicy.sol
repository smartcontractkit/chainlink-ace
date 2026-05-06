// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IPolicyEngine} from "../interfaces/IPolicyEngine.sol";
import {ICertifiedActionValidator} from "../interfaces/ICertifiedActionValidator.sol";
import {CertifiedActionLib} from "../libraries/CertifiedActionLib.sol";
import {Policy} from "../core/Policy.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title CertifiedActionValidatorPolicy
 * @notice Policy to validate actions using certified action permits.
 * @dev This policy implements the ICertifiedActionValidator interface to manage and validate permits for actions.
 *      It uses EIP-712 for secure off-chain signing of permits and OpenZeppelin's ECDSA library for signature
 * verification.
 *
 *      The policy maintains a list of authorized issuers who can sign permits. Each permit includes details such as
 *      the caller, subject, action selector, parameters, metadata, maximum uses, and expiry time.
 *
 *      The policy supports two modes of operation:
 *      1. Pre-presented permits: Permits that have been presented and stored on-chain before the action is attempted.
 *      Note that the act of presenting a permit overrides any ability for a context permit for the same intent.
 *      2. Contextual permits: Permits that are provided in the context of the action attempt.
 *
 *      The policy checks the validity of the permit based on its signature, expiry, and usage limits before allowing
 *      the action to proceed.
 *
 *      Custom implementations can extend this base policy to add additional validation logic or storage as needed.
 */
contract CertifiedActionValidatorPolicy is Policy, EIP712Upgradeable, ICertifiedActionValidator {
  using CertifiedActionLib for ICertifiedActionValidator.Permit;

  /// @notice The readable name of the EIP712 signing domain.
  string private constant EIP712_DOMAIN = "CertifiedActionValidator";
  /// @notice The version of the EIP712 signing domain.
  string private constant EIP712_VERSION = "1";

  struct StoredPermit {
    uint64 maxUses;
    uint48 expiry;
    uint64 uses;
    bool revoked;
  }

  /// @custom:storage-location erc7201:chainlink.ace.CertifiedActionValidatorPolicy
  struct CertifiedActionValidatorPolicyStorage {
    mapping(bytes32 permitId => StoredPermit storedPermit) storedPermits;
    mapping(address issuerKey => bool allowed) issuers;
    mapping(bytes32 intentHash => bytes32 permitId) intentToPermit;
    mapping(bytes32 permitId => address issuer) permitIssuer;
  }

  /// @notice Error emitted when a permit signature format is invalid.
  error InvalidSignatureFormat(ECDSA.RecoverError error, bytes32 errArg);

  // keccak256(abi.encode(uint256(keccak256("chainlink.ace.CertifiedActionValidatorPolicy")) - 1)) &
  // ~bytes32(uint256(0xff))
  // solhint-disable-next-line const-name-snakecase
  bytes32 private constant CertifiedActionValidatorPolicyStorageLocation =
    0x44c002381c586ebdb00ba1d2de58b2e7b37c8c224e74aff0ea92c173550eb800;

  function _getCertifiedActionValidatorPolicyStorage()
    internal
    pure
    returns (CertifiedActionValidatorPolicyStorage storage $)
  {
    // solhint-disable-next-line no-inline-assembly
    assembly {
      $.slot := CertifiedActionValidatorPolicyStorageLocation
    }
  }

  function typeAndVersion() public pure virtual override returns (string memory) {
    return "CertifiedActionValidatorPolicy 1.0.0";
  }

  /**
   * @notice Configures the policy by initializing the EIP712 domain separator and setting the contract owner as the
   * initial signer.
   * @dev No parameters are expected or decoded from the input. The EIP712 domain is initialized with the constants
   * `EIP712_DOMAIN` and `EIP712_VERSION. The initial owner is added as the first authorized signer for approving
   * requests.
   */
  function configure(bytes calldata) internal virtual override onlyInitializing {
    __EIP712_init(EIP712_DOMAIN, EIP712_VERSION);
  }

  /// @inheritdoc ICertifiedActionValidator
  function present(Permit memory permit, bytes memory signature) public virtual {
    CertifiedActionValidatorPolicyStorage storage $ = _getCertifiedActionValidatorPolicyStorage();
    if ($.permitIssuer[permit.permitId] != address(0)) {
      revert PermitAlreadyPresented(permit.permitId);
    } else if ($.storedPermits[permit.permitId].revoked) {
      revert PermitAlreadyRevoked(permit.permitId);
    } else if (!_validatePermitSignature(hashTypedDataV4Permit(permit), signature)) {
      revert InvalidSignature(permit.permitId);
    }
    bytes32 intentHash = _hashIntent(permit.caller, permit.subject, permit.selector, permit.parameters);
    $.intentToPermit[intentHash] = permit.permitId;
    $.storedPermits[permit.permitId] =
      StoredPermit(permit.maxUses, permit.expiry, $.storedPermits[permit.permitId].uses, false);
    $.permitIssuer[permit.permitId] = _recoverIssuer(hashTypedDataV4Permit(permit), signature);
    _storePresentedPermitHook(permit);
    emit PermitStored(permit.permitId);
  }

  /// @inheritdoc ICertifiedActionValidator
  function check(Permit memory permit, bytes memory signature) public view virtual returns (bool) {
    return _validatePermitSignature(hashTypedDataV4Permit(permit), signature);
  }

  /// @inheritdoc ICertifiedActionValidator
  function revoke(bytes32 permitId) public virtual onlyOwner {
    CertifiedActionValidatorPolicyStorage storage $ = _getCertifiedActionValidatorPolicyStorage();
    $.storedPermits[permitId].revoked = true;
    emit PermitRevoked(permitId);
  }

  /// @inheritdoc ICertifiedActionValidator
  function getUsage(bytes32 permitId) public view virtual returns (uint256) {
    CertifiedActionValidatorPolicyStorage storage $ = _getCertifiedActionValidatorPolicyStorage();
    return $.storedPermits[permitId].uses;
  }

  /// @inheritdoc ICertifiedActionValidator
  function allowIssuer(bytes memory issuerKey) public virtual onlyOwner {
    CertifiedActionValidatorPolicyStorage storage $ = _getCertifiedActionValidatorPolicyStorage();
    address issuerAddress = abi.decode(issuerKey, (address));
    if ($.issuers[issuerAddress]) {
      revert IssuerAllowedAlreadySet(issuerKey, true);
    }
    $.issuers[issuerAddress] = true;
    emit IssuerAllowed(issuerKey);
  }

  /// @inheritdoc ICertifiedActionValidator
  function disAllowIssuer(bytes memory issuerKey) public virtual onlyOwner {
    CertifiedActionValidatorPolicyStorage storage $ = _getCertifiedActionValidatorPolicyStorage();
    address issuerAddress = abi.decode(issuerKey, (address));
    if (!$.issuers[issuerAddress]) {
      revert IssuerAllowedAlreadySet(issuerKey, false);
    }
    $.issuers[issuerAddress] = false;
    emit IssuerDisAllowed(issuerKey);
  }

  /// @inheritdoc ICertifiedActionValidator
  function getIssuerAllowed(bytes memory issuerKey) public view virtual returns (bool) {
    address issuerAddress = abi.decode(issuerKey, (address));
    return _getCertifiedActionValidatorPolicyStorage().issuers[issuerAddress];
  }

  /**
   * @notice Computes the EIP-712 typed data hash for a Permit
   * @dev Public function that combines operation hashing with EIP-712 domain hashing.
   *      Used for signature generation and verification.
   * @param permit The operation to hash
   * @return The EIP-712 compliant typed data hash ready for signing
   */
  function hashTypedDataV4Permit(Permit memory permit) public view returns (bytes32) {
    return _hashTypedDataV4(permit._hashPermit());
  }

  function _validatePrePresentedPermit(
    address caller,
    address subject,
    bytes4 selector,
    bytes[] memory parameters
  )
    internal
    view
    returns (bool)
  {
    CertifiedActionValidatorPolicyStorage storage $ = _getCertifiedActionValidatorPolicyStorage();
    bytes32 intentHash = _hashIntent(caller, subject, selector, parameters);

    bytes32 permitId = $.intentToPermit[intentHash];
    if (permitId == 0) {
      return false;
    }
    StoredPermit storage storedPermit = $.storedPermits[permitId];
    return _validatePermitNotRevoked(permitId) && _validatePermitIssuerNotRevoked($.permitIssuer[permitId])
      && _validatePermitExpiry(storedPermit.expiry) && _validatePermitMaxUses(storedPermit.uses, storedPermit.maxUses)
      && _validatePrePresentedPermitHook(permitId, caller, subject, selector, parameters);
  }

  /**
   * @notice Validates a signed permit against the action parameters.
   * @dev This function does not verify whether a pre-presented permit exists for the same intent. The `run()` function
   *      performs that check before invoking this function. Callers invoking this function directly must ensure no
   *      pre-presented permit exists for the intent to preserve permit priority semantics.
   */
  function _validateSignedPermit(
    address caller,
    address subject,
    bytes4 selector,
    bytes[] memory parameters,
    SignedPermit memory signedPermit
  )
    internal
    view
    returns (bool)
  {
    CertifiedActionValidatorPolicyStorage storage $ = _getCertifiedActionValidatorPolicyStorage();

    Permit memory permit = signedPermit.permit;
    bytes32 permitIntentHash = _hashIntent(permit.caller, permit.subject, permit.selector, permit.parameters);

    // ensures the permit exactly matches the intended action
    if (_hashIntent(caller, subject, selector, parameters) != permitIntentHash) {
      return false;
    }

    bytes32 permitHash = hashTypedDataV4Permit(permit);
    // _validatePermitSignature already checks if the issuer is allowed
    if (!_validatePermitSignature(permitHash, signedPermit.signature)) {
      return false;
    }

    return _validatePermitNotRevoked(permit.permitId) && _validatePermitExpiry(permit.expiry)
      && _validatePermitMaxUses($.storedPermits[permit.permitId].uses, permit.maxUses)
      && _validateSignedPermitHook(permit, caller, subject, selector, parameters);
  }

  function _validatePermitNotRevoked(bytes32 permitId) internal view returns (bool) {
    CertifiedActionValidatorPolicyStorage storage $ = _getCertifiedActionValidatorPolicyStorage();
    return !$.storedPermits[permitId].revoked;
  }

  function _validatePermitExpiry(uint48 expiry) internal view returns (bool) {
    return expiry == 0 || block.timestamp <= expiry;
  }

  function _validatePermitMaxUses(uint64 currentUses, uint64 maxUses) internal pure returns (bool) {
    return maxUses == 0 || currentUses < maxUses;
  }

  function _validatePermitSignature(bytes32 permitHash, bytes memory signature) internal view virtual returns (bool) {
    address issuer = _recoverIssuer(permitHash, signature);
    return _validatePermitIssuerNotRevoked(issuer);
  }

  function _recoverIssuer(bytes32 permitHash, bytes memory signature) internal view virtual returns (address) {
    (address recovered, ECDSA.RecoverError error, bytes32 errArg) = ECDSA.tryRecover(permitHash, signature);

    if (error != ECDSA.RecoverError.NoError) {
      revert InvalidSignatureFormat(error, errArg);
    }

    return recovered;
  }

  function _validatePermitIssuerNotRevoked(address issuer) internal view returns (bool) {
    return issuer != address(0) && _getCertifiedActionValidatorPolicyStorage().issuers[issuer];
  }

  function _hashIntent(
    address caller,
    address subject,
    bytes4 selector,
    bytes[] memory parameters
  )
    internal
    pure
    virtual
    returns (bytes32)
  {
    return keccak256(abi.encode(caller, subject, selector, parameters));
  }

  // other implementations can extend this to store additional data
  function _storePresentedPermitHook(Permit memory /*permit*/ ) internal virtual {}

  // other implementations can extend this to validate the pre-presented permit further
  function _validatePrePresentedPermitHook(
    bytes32, /*permitId*/
    address, /*caller*/
    address, /*subject*/
    bytes4, /*selector*/
    bytes[] memory /*parameters*/
  )
    internal
    view
    virtual
    returns (bool)
  {
    return true;
  }

  // other implementations can extend this to validate the permit further
  function _validateSignedPermitHook(
    Permit memory, /*permit*/
    address, /*caller*/
    address, /*subject*/
    bytes4, /*selector*/
    bytes[] memory /*parameters*/
  )
    internal
    view
    virtual
    returns (bool)
  {
    return true;
  }

  function run(
    address caller,
    address subject,
    bytes4 selector,
    bytes[] calldata parameters,
    bytes calldata context
  )
    public
    view
    override
    returns (IPolicyEngine.PolicyResult)
  {
    bytes32 intentHash = _hashIntent(caller, subject, selector, parameters);
    if (_getCertifiedActionValidatorPolicyStorage().intentToPermit[intentHash] != 0) {
      // check for and validate a pre-presented permit
      if (!_validatePrePresentedPermit(caller, subject, selector, parameters)) {
        revert IPolicyEngine.PolicyRejected("no valid pre-presented permit found");
      }
    } else if (context.length > 0) {
      // attempt to decode a permit from the context
      if (!_validateSignedPermit(caller, subject, selector, parameters, abi.decode(context, (SignedPermit)))) {
        revert IPolicyEngine.PolicyRejected("invalid signed permit in context");
      }
    } else {
      revert IPolicyEngine.PolicyRejected("no valid permit found");
    }
    return IPolicyEngine.PolicyResult.Continue;
  }

  /**
   * @notice Runs after the policy check if the check was successful to update usage counts.
   */
  function postRun(
    address caller,
    address subject,
    bytes4 selector,
    bytes[] calldata parameters,
    bytes calldata context
  )
    public
    override
    onlyPolicyEngine
  {
    CertifiedActionValidatorPolicyStorage storage $ = _getCertifiedActionValidatorPolicyStorage();
    // Always use intent hash to determine which permit was validated
    bytes32 intentHash = _hashIntent(caller, subject, selector, parameters);
    bytes32 permitId = $.intentToPermit[intentHash];
    if (permitId != 0) {
      // Pre-presented permit was used
      $.storedPermits[permitId].uses++;
      emit PermitUsed(permitId);
    } else if (context.length > 0) {
      // Contextual permit was used and validated
      SignedPermit memory signedPermit = abi.decode(context, (SignedPermit));
      $.storedPermits[signedPermit.permit.permitId].uses++;
      emit PermitUsed(signedPermit.permit.permitId);
    }
  }
}
