// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {Policy} from "@chainlink/policy-management/core/Policy.sol";

/**
 * @title GrantorPolicy
 * @notice A policy that allows a set of signers to approve requests for transfers.
 * @dev This policy inherit OpenZeppelin's EIP712Upgradeable and use EIP712 for signing and verifying requests.
 */
contract GrantorPolicy is Policy, EIP712Upgradeable {
  /// @notice The readable name of the EIP712 signing domain.
  string private constant EIP712_DOMAIN = "GrantorPolicy";
  /// @notice The version of the EIP712 signing domain.
  string private constant EIP712_VERSION = "1";
  /// @notice The EIP712 type hash.
  bytes32 private typeHash =
    keccak256("TransferInfo(address from,address to,uint256 amount,uint256 nonce,uint48 expiresAt)");

  /// @notice The context to be passed to the policy before the protected method call.
  struct GrantorContext {
    /// @notice The expiration time of the transfer request.
    uint48 expiresAt;
    /// @notice The signature of the transfer request.
    bytes signature;
  }

  /// @notice The payload to sign.
  struct TransferInfo {
    /// @notice The address of the sender.
    address from;
    /// @notice The address of the recipient.
    address to;
    /// @notice The amount to transfer.
    uint256 amount;
    /// @notice The nonce of the sender.
    uint256 nonce;
    /// @notice The expiration time of the transfer request.
    uint48 expiresAt;
  }

  /**
   * @notice Emitted when a signer is added.
   * @param signer The address of the signer.
   */
  event SignerAdded(address signer);
  /**
   * @notice Emitted when a signer is removed.
   * @param signer The address of the signer.
   */
  event SignerRemoved(address signer);

  /**
   * @notice Emmited when a nonce is incremented.
   * @param sender The address of the sender.
   * @param nonce The new nonce of the sender.
   */
  event NonceIncremented(address sender, uint256 nonce);

  /// @custom:storage-location erc7201:policy-management.GrantorPolicy
  struct GrantorPolicyStorage {
    /// @notice Stores signers.
    mapping(address signer => bool isSigner) signers;
    /// @notice Stores the nonces for each sender.
    mapping(address sender => uint256 nonce) senderNonces;
  }

  // keccak256(abi.encode(uint256(keccak256("policy-management.GrantorPolicy")) - 1)) & ~bytes32(uint256(0xff))
  bytes32 private constant GrantorPolicyStorageLocation =
    0x73c86de5c1d6e2055989efa21b2069aa31f3cb1ed639ba48f35d8eee24125300;

  function _getGrantorPolicyStorage() private pure returns (GrantorPolicyStorage storage $) {
    assembly {
      $.slot := GrantorPolicyStorageLocation
    }
  }

  /**
   * @notice Configures the policy by initializing the EIP712 domain separator and setting the contract owner as the
   * initial signer.
   * @dev No parameters are expected or decoded from the input. The EIP712 domain is initialized with the constants
   * `EIP712_DOMAIN` and `EIP712_VERSION. The initial owner is added as the first authorized signer for approving
   * requests.
   */
  function configure(bytes calldata) internal override onlyInitializing {
    __EIP712_init(EIP712_DOMAIN, EIP712_VERSION);
    address owner = owner();
    GrantorPolicyStorage storage $ = _getGrantorPolicyStorage(); // Gas optimization: single storage reference
    $.signers[owner] = true;
    emit SignerAdded(owner);
  }

  /**
   * @notice Adds a signer that can approve requests. Revert if the signer is already present.
   * @param signer The signer to add.
   */
  function addSigner(address signer) public onlyOwner {
    require(signer != address(0), "signer cannot be the zero address");
    GrantorPolicyStorage storage $ = _getGrantorPolicyStorage(); // Gas optimization: single storage reference
    require(!$.signers[signer], "address is already a signer");
    $.signers[signer] = true;
    emit SignerAdded(signer);
  }

  /**
   * @notice Removes a signer from the list of signers that can approve requests. Revert if the signer is not present.
   * @param signer The signer to remove.
   */
  function removeSigner(address signer) public onlyOwner {
    GrantorPolicyStorage storage $ = _getGrantorPolicyStorage(); // Gas optimization: single storage reference
    require($.signers[signer], "address is not signer");
    $.signers[signer] = false;
    emit SignerRemoved(signer);
  }

  /**
   * @notice Retrieve the current nonce for a sender.
   * @param sender The sender to check.
   * @return nonce The current nonce for the sender.
   */
  function senderNonce(address sender) public view returns (uint256) {
    GrantorPolicyStorage storage $ = _getGrantorPolicyStorage();
    return $.senderNonces[sender];
  }

  /**
   * @notice Hashes the transfer information using EIP712.
   * @param info The transfer information to hash.
   * @return hash hash of the transfer information.
   */
  function hash(TransferInfo memory info) public view returns (bytes32) {
    return
      _hashTypedDataV4(keccak256(abi.encode(typeHash, info.from, info.to, info.amount, info.nonce, info.expiresAt)));
  }

  /**
   * @notice Verifies the signature of the transfer information.
   * @param info The transfer information to verify.
   * @param signature The signature to verify.
   * @return isSignatureValid True if the signature is valid, false otherwise.
   */
  function verify(TransferInfo memory info, bytes memory signature) public view returns (bool) {
    (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash(info), signature);
    if (err != ECDSA.RecoverError.NoError) {
      return false;
    }
    GrantorPolicyStorage storage $ = _getGrantorPolicyStorage();
    return $.signers[signer];
  }

  /**
   * @notice Increments the nonce for the sender. This is used to invalidate signatures and prevent replay attacks.
   */
  function incrementNonce() public {
    GrantorPolicyStorage storage $ = _getGrantorPolicyStorage(); // Gas optimization: single storage reference
    uint256 newNonce = ++$.senderNonces[msg.sender];
    emit NonceIncremented(msg.sender, newNonce);
  }

  /**
   * @notice Function to be called by the policy engine to check if execution is allowed.
   * @param parameters [from(address), to(address), amount(uint256)] The parameters of the called method.
   * @param context The GrantorContext in bytes that passed to the policy before the method call.
   * @return result The result of the policy check.
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
    // expected parameters: [from(address), to(address), amount(uint256)]
    require(parameters.length == 3, "expected 3 parameters");

    address from = abi.decode(parameters[0], (address));
    address to = abi.decode(parameters[1], (address));
    uint256 amount = abi.decode(parameters[2], (uint256));

    GrantorContext memory grantorContext = abi.decode(context, (GrantorContext));

    if (grantorContext.expiresAt <= block.timestamp) {
      return IPolicyEngine.PolicyResult.Rejected;
    }

    GrantorPolicyStorage storage $ = _getGrantorPolicyStorage(); // Gas optimization: single storage reference
    TransferInfo memory info = TransferInfo({
      from: from,
      to: to,
      amount: amount,
      nonce: $.senderNonces[from],
      expiresAt: grantorContext.expiresAt
    });

    if (!verify(info, grantorContext.signature)) {
      return IPolicyEngine.PolicyResult.Rejected;
    }
    return IPolicyEngine.PolicyResult.Continue;
  }

  /**
   * @notice Runs after the policy check if the check was successful, and updates the sender's nonce to prevent
   * signature replay attacks. This function is called by the policy engine after run() succeeds but before the
   * protected target function executes.
   * @param parameters [from(address), to(address), amount(uint256)] The parameters of the called method.
   */
  function postRun(
    address, /*caller*/
    address, /*subject*/
    bytes4, /*selector*/
    bytes[] calldata parameters,
    bytes calldata /*context*/
  )
    public
    override
    onlyPolicyEngine
  {
    // expected parameters: [from(address), to(address), amount(uint256)]
    require(parameters.length == 3, "expected 3 parameters");

    address from = abi.decode(parameters[0], (address));

    GrantorPolicyStorage storage $ = _getGrantorPolicyStorage(); // Gas optimization: single storage reference
    uint256 newNonce = ++$.senderNonces[from];
    emit NonceIncremented(msg.sender, newNonce);
  }
}
