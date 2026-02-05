// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IPolicyEngine} from "../interfaces/IPolicyEngine.sol";
import {ICertifiedActionValidator} from "../interfaces/ICertifiedActionValidator.sol";
import {CertifiedActionValidatorPolicy} from "./CertifiedActionValidatorPolicy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title CertifiedActionERC20TransferValidatorPolicy
 * @notice Policy to validate ERC20 token transfers using certified action permits.
 * @dev This policy extends the CertifiedActionValidatorPolicy to specifically handle ERC20 token transfers.
 *      It overrides the intent hashing and validation logic to match based on the sender, token address and the
 *      ERC20 transfer from/to instead of the entire list of parameters supplied to the policy. Max transfer amount
 *      enforcement is performed in the validation hooks.
 *
 * NOTE: The permit parameters are encoded differently than the parameters that will be provided to the policy during
 * validation. The permit parameters include the maximum amount allowed, while the policy parameters during validation
 * will include the actual amount being transferred.
 *
 *      The policy expects the following parameters:
 *      - parameters[0]: address of the sender/from (address)
 *      - parameters[1]: address of the recipient/to (address)
 *      - parameters[2]: amount to transfer (uint256)
 *
 *      The permit's parameters are expected to be encoded as:
 *      - permit.parameters[0]: address of the from/sender (address)
 *      - permit.parameters[1]: address of the recipient/to (address)
 *      - permit.parameters[2]: maximum amount allowed to transfer (uint256)
 *
 *      If the attempted transfer amount exceeds the maximum allowed amount, the validation will fail.
 */
contract CertifiedActionERC20TransferValidatorPolicy is CertifiedActionValidatorPolicy {
  /// @custom:storage-location erc7201:chainlink.ace.CertifiedActionERC20TransferValidatorPolicy
  struct CertifiedActionERC20TransferValidatorPolicyStorage {
    mapping(bytes32 permitId => uint256 maxAmount) maxTransferAmounts;
  }

  // keccak256(abi.encode(uint256(keccak256("chainlink.ace.CertifiedActionERC20TransferValidatorPolicy")) - 1)) &
  // ~bytes32(uint256(0xff))
  // solhint-disable-next-line const-name-snakecase
  bytes32 private constant CertifiedActionERC20TransferValidatorPolicyStorageLocation =
    0xb6ec1194d7b5ec102788638ac9b642ebad3ce1075cc2da50b257f0984f300800;

  function _getCertifiedActionERC20TransferValidatorPolicyStorage()
    private
    pure
    returns (CertifiedActionERC20TransferValidatorPolicyStorage storage $)
  {
    // solhint-disable-next-line no-inline-assembly
    assembly {
      $.slot := CertifiedActionERC20TransferValidatorPolicyStorageLocation
    }
  }

  function typeAndVersion() public pure virtual override returns (string memory) {
    return "CertifiedActionERC20TransferValidatorPolicy 1.0.0";
  }

  /**
   * @dev Overrides the intent hash to be based on the ERC20 token address, the funds sender and recipient address.
   * The selector is not included in the hash to allow the same permit to be used for both `transfer` and
   * `transferFrom` but a check is performed to ensure the selector is either `transfer` or `transferFrom`.
   * The parameters provided to the policy are expected to be:
   *  - parameters[0]: address of the sender/from (address)
   *  - parameters[1]: address of the recipient/to (address)
   *  - parameters[2]: amount to transfer (uint256)
   */
  function _hashIntent(
    address caller,
    address subject,
    bytes4 selector,
    bytes[] memory parameters
  )
    internal
    pure
    virtual
    override
    returns (bytes32)
  {
    if (parameters.length != 3) {
      revert InvalidParameters("expected 3 policy parameters");
    }
    // restrict to ERC20 transfer family (transfer and transferFrom)
    if (selector != IERC20.transfer.selector && selector != IERC20.transferFrom.selector) {
      revert InvalidParameters("unsupported selector");
    }
    return keccak256(abi.encode(caller, subject, parameters[0], parameters[1]));
  }

  /**
   * @dev Stores the maximum transfer amount from the permit's intent which will be used to validate the transfer amount
   * during the validation hook.
   *
   * The permit parameters are expected to be encoded as:
   * - permit.parameters[0]: address of the from/sender (address)
   * - permit.parameters[1]: address of the recipient/to (address)
   * - permit.parameters[2]: maximum amount allowed to transfer (uint256)
   *
   * If the intent is not correctly encoded, the permit presentation will revert.
   */
  function _storePresentedPermitHook(Permit memory permit) internal virtual override {
    if (permit.parameters.length != 3) {
      revert InvalidParameters("expected 3 permit parameters");
    }
    uint256 maxAmount = abi.decode(permit.parameters[2], (uint256));

    _getCertifiedActionERC20TransferValidatorPolicyStorage().maxTransferAmounts[permit.permitId] = maxAmount;
  }

  /**
   * @dev Validates that the attempted transfer amount does not exceed the maximum amount specified in the presented
   * permit.
   *
   * The parameters provided to the policy are expected to be (extracted by ERC20TransferExtractor):
   *  - parameters[0]: address of the sender/from (address)
   *  - parameters[1]: address of the recipient/to (address)
   *  - parameters[2]: amount to transfer (uint256)
   */
  function _validatePrePresentedPermitHook(
    bytes32 permitId,
    address, /*caller*/
    address, /*subject*/
    bytes4, /*selector*/
    bytes[] memory parameters
  )
    internal
    view
    virtual
    override
    returns (bool)
  {
    if (parameters.length != 3) {
      revert InvalidParameters("expected 3 policy parameters");
    }
    uint256 attemptedAmount = abi.decode(parameters[2], (uint256));

    CertifiedActionERC20TransferValidatorPolicyStorage storage $ =
      _getCertifiedActionERC20TransferValidatorPolicyStorage();
    if ($.maxTransferAmounts[permitId] > 0 && attemptedAmount > $.maxTransferAmounts[permitId]) {
      return false;
    }

    return true;
  }

  /**
   * @dev Validates that the attempted transfer amount does not exceed the maximum amount specified in the permit's
   * intent.
   *
   * The parameters provided to the policy are expected to be (extracted by ERC20TransferExtractor):
   *  - parameters[0]: address of the sender/from (address)
   *  - parameters[1]: address of the recipient/to (address)
   *  - parameters[2]: amount to transfer (uint256)
   *
   * The permit parameters are expected to have been encoded as:
   * - permit.parameters[0]: address of the from/sender (address)
   * - permit.parameters[1]: address of the recipient/to (address)
   * - permit.parameters[2]: maximum amount allowed to transfer (uint256)
   */
  function _validateSignedPermitHook(
    Permit memory permit,
    address, /*caller*/
    address, /*subject*/
    bytes4, /*selector*/
    bytes[] memory parameters
  )
    internal
    pure
    virtual
    override
    returns (bool)
  {
    if (parameters.length != 3) {
      revert InvalidParameters("expected 3 policy parameters");
    }
    uint256 attemptedAmount = abi.decode(parameters[2], (uint256));

    if (permit.parameters.length != 3) {
      revert InvalidParameters("expected 3 permit parameters");
    }
    uint256 max = abi.decode(permit.parameters[2], (uint256));

    if (max > 0 && attemptedAmount > max) {
      return false;
    }

    return true;
  }

  /// @inheritdoc ICertifiedActionValidator
  /// @dev Overrides the check function to ensure the permit is for an ERC20 transfer/transferFrom operation.
  function check(Permit memory permit, bytes memory signature) public view virtual override returns (bool) {
    if (
      permit.parameters.length != 3
        || (permit.selector != IERC20.transfer.selector && permit.selector != IERC20.transferFrom.selector)
    ) {
      return false;
    }
    return super.check(permit, signature);
  }
}
