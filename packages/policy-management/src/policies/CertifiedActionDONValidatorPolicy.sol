// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {Policy} from "../core/Policy.sol";
import {ICertifiedActionValidator} from "../interfaces/ICertifiedActionValidator.sol";
import {IReceiver} from "@chainlink/contracts/src/v0.8/keystone/interfaces/IReceiver.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {KeystoneFeedDefaultMetadataLib} from
  "@chainlink/contracts/src/v0.8/keystone/lib/KeystoneFeedDefaultMetadataLib.sol";
import {CertifiedActionValidatorPolicy} from "./CertifiedActionValidatorPolicy.sol";

/**
 * @title CertifiedActionDONValidatorPolicy
 * @notice Policy to allow a DON (via the KeystoneForwarder) to register certified action permits.
 */
contract CertifiedActionDONValidatorPolicy is CertifiedActionValidatorPolicy, IReceiver {
  using KeystoneFeedDefaultMetadataLib for bytes;

  /// @custom:storage-location erc7201:chainlink.ace.CertifiedActionDONValidatorPolicy
  struct CertifiedActionDONValidatorPolicyStorage {
    address keystoneForwarder;
  }

  error InvalidKeystoneForwarder();
  error UnauthorizedKeystoneForwarder(address sender);

  event KeystoneForwarderSet(address indexed forwarder);

  // keccak256(abi.encode(uint256(keccak256("chainlink.ace.CertifiedActionDONValidatorPolicy")) - 1)) &
  // ~bytes32(uint256(0xff))
  // solhint-disable-next-line const-name-snakecase
  bytes32 private constant CertifiedActionDONValidatorPolicyStorageLocation =
    0x711adf10c29d34d49c4016af4078565957bc5869fd5988a8fc28cd0cedd04400;

  function _getCertifiedActionDONValidatorPolicyStorage()
    private
    pure
    returns (CertifiedActionDONValidatorPolicyStorage storage $)
  {
    // solhint-disable-next-line no-inline-assembly
    assembly {
      $.slot := CertifiedActionDONValidatorPolicyStorageLocation
    }
  }

  function typeAndVersion() public pure virtual override returns (string memory) {
    return "CertifiedActionDONValidatorPolicy 1.0.0";
  }

  /**
   * @notice Configures the policy with the Keystone Forwarder address.
   */
  function configure(bytes calldata parameters) internal override onlyInitializing {
    _setKeystoneForwarder(abi.decode(parameters, (address)));
    super.configure(parameters);
  }

  function setKeystoneForwarder(address keystoneForwarder) external onlyOwner {
    _setKeystoneForwarder(keystoneForwarder);
  }

  function getKeystoneForwarder() external view returns (address) {
    return _getCertifiedActionDONValidatorPolicyStorage().keystoneForwarder;
  }

  /**
   * @notice Handles incoming reports from the trusted Keystone forwarder and processes the permit.
   */
  function onReport(bytes calldata metadata, bytes calldata report) external virtual override {
    (, address workflowOwner,) = metadata._extractMetadataInfo();
    present(abi.decode(report, (ICertifiedActionValidator.Permit)), abi.encode(workflowOwner));
  }

  /**
   * @notice Modifies the present function to be callable by the Keystone Forwarder only (via onReport).
   * The signature parameter is expected to be the encoded workflow owner address as extracted from the
   * OCR report metadata.
   */
  function present(Permit memory permit, bytes memory workflowOwnerAddress) public virtual override {
    if (msg.sender != _getCertifiedActionDONValidatorPolicyStorage().keystoneForwarder) {
      revert UnauthorizedKeystoneForwarder(msg.sender);
    }
    super.present(permit, workflowOwnerAddress);
  }

  /// @inheritdoc IERC165
  function supportsInterface(bytes4 interfaceId) public pure virtual override(IERC165, Policy) returns (bool) {
    return interfaceId == type(IReceiver).interfaceId || interfaceId == type(IERC165).interfaceId;
  }

  function _setKeystoneForwarder(address keystoneForwarder) internal {
    if (keystoneForwarder == address(0)) {
      revert InvalidKeystoneForwarder();
    }
    _getCertifiedActionDONValidatorPolicyStorage().keystoneForwarder = keystoneForwarder;
    emit KeystoneForwarderSet(keystoneForwarder);
  }

  /**
   * @notice Permits presented by the DON supply the workflow owner in the signature field. The workflow owner
   * is directly validated as an allowed issuer.
   */
  function _validatePermitSignature(
    bytes32, /*permitHash*/
    bytes memory workflowOwnerAddress
  )
    internal
    view
    override
    returns (bool)
  {
    return getIssuerAllowed(workflowOwnerAddress);
  }

  /**
   * @notice With DON permits, the "signature" parameter contains the encoded workflow owner address,
   *      not an ECDSA signature. We decode and return the workflow owner directly.
   */
  function _recoverIssuer(
    bytes32, /*permitHash*/
    bytes memory workflowOwnerAddress
  )
    internal
    pure
    override
    returns (address)
  {
    return abi.decode(workflowOwnerAddress, (address));
  }

  /**
   * @notice Overrides the check function to ensure a permit issued from an allowed workflow owner is considered valid.
   */
  function check(Permit memory, bytes memory workflowOwnerAddress) public view virtual override returns (bool) {
    return getIssuerAllowed(workflowOwnerAddress);
  }

  /**
   * @notice Overrides the validatePermitHook function to unconditionally reject contextual permits as only
   * pre-presented permits from the DON are considered valid.
   */
  function _validateSignedPermitHook(
    Permit memory, /*permit*/
    address, /*caller*/
    address, /*subject*/
    bytes4, /*selector*/
    bytes[] memory /*parameters*/
  )
    internal
    pure
    override
    returns (bool)
  {
    return false;
  }
}
