// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC7943Fungible} from "./interfaces/IERC7943.sol";
import {ComplianceTokenStoreERC7943} from "./ComplianceTokenStoreERC7943.sol";
import {PolicyProtected} from "@chainlink/policy-management/core/PolicyProtected.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

/**
 * @title ComplianceTokenERC7943
 * @notice A policy-protected ERC-20 compliant token implementing the ERC-7943 Universal RWA Interface.
 *
 * @dev This implementation provides compliance features for Real World Assets:
 *
 * **Whitelist Behavior:**
 * - Only whitelisted addresses can transact (send/receive tokens)
 * - The canTransact() function checks whitelist status
 * - Whitelist management is policy-protected
 *
 * **Frozen Token Behavior:**
 * - Frozen tokens cannot be transferred by the account holder
 * - setFrozenTokens() overwrites the frozen amount (like approve)
 * - Supports "pre-freezing" tokens before they are received
 * - forcedTransfer may transfer frozen tokens (administrative action)
 *
 * **Key Features:**
 * - ERC-7943 compliant interface for RWA interoperability
 * - Policy-protected administrative functions
 * - Integration with policy engine for complex compliance rules
 */
contract ComplianceTokenERC7943 is Initializable, PolicyProtected, ComplianceTokenStoreERC7943, IERC20, IERC7943Fungible {
  /// @notice Emitted when an account's whitelist status is changed.
  /// @param account The address whose status was changed.
  /// @param status The new whitelist status (true = whitelisted, false = not whitelisted).
  event Whitelisted(address indexed account, bool status);

  /**
   * @dev Initializes the contract with the provided token metadata and assigns policy engine.
   * @param tokenName The name of the token.
   * @param tokenSymbol The symbol of the token.
   * @param tokenDecimals The number of decimals to use for display purposes.
   * @param policyEngine The address of the policy engine contract.
   */
  function initialize(
    string calldata tokenName,
    string calldata tokenSymbol,
    uint8 tokenDecimals,
    address policyEngine
  )
    public
    virtual
    initializer
  {
    __ComplianceTokenERC7943_init(tokenName, tokenSymbol, tokenDecimals, policyEngine);
  }

  /**
   * @dev Upgradeable init function to be used by a token implementation contract.
   * @param tokenName The name of the token.
   * @param tokenSymbol The symbol of the token.
   * @param tokenDecimals The number of decimals to use for display purposes.
   * @param policyEngine The address of the policy engine contract.
   */
  function __ComplianceTokenERC7943_init(
    string memory tokenName,
    string memory tokenSymbol,
    uint8 tokenDecimals,
    address policyEngine
  )
    internal
    onlyInitializing
  {
    __PolicyProtected_init(msg.sender, policyEngine);
    __ComplianceTokenERC7943_init_unchained(tokenName, tokenSymbol, tokenDecimals);
  }

  /**
   * @dev Unchained upgradeable init function to be used by a token implementation contract.
   * @param tokenName The name of the token.
   * @param tokenSymbol The symbol of the token.
   * @param tokenDecimals The number of decimals to use for display purposes.
   */
  function __ComplianceTokenERC7943_init_unchained(
    string memory tokenName,
    string memory tokenSymbol,
    uint8 tokenDecimals
  )
    internal
    onlyInitializing
  {
    ComplianceTokenStorage storage $ = getComplianceTokenStorage();
    $.tokenName = tokenName;
    $.tokenSymbol = tokenSymbol;
    $.tokenDecimals = tokenDecimals;
  }

  // ** ERC-20 Methods **

  /// @inheritdoc IERC20
  function totalSupply() public view virtual override returns (uint256) {
    return getComplianceTokenStorage().totalSupply;
  }

  /// @inheritdoc IERC20
  function balanceOf(address account) public view virtual override returns (uint256) {
    return getComplianceTokenStorage().balances[account];
  }

  /// @inheritdoc IERC20
  function transfer(address to, uint256 amount) public virtual override runPolicy returns (bool) {
    _transfer(msg.sender, to, amount);
    return true;
  }

  /// @inheritdoc IERC20
  function allowance(address owner, address spender) public view virtual override returns (uint256) {
    return getComplianceTokenStorage().allowances[owner][spender];
  }

  /// @inheritdoc IERC20
  function approve(address spender, uint256 amount) public virtual override runPolicy returns (bool) {
    _approve(msg.sender, spender, amount, true);
    return true;
  }

  /// @inheritdoc IERC20
  function transferFrom(address from, address to, uint256 amount) public virtual override runPolicy returns (bool) {
    _spendAllowance(from, msg.sender, amount);
    _transfer(from, to, amount);
    return true;
  }

  // ** End ERC-20 Methods **

  // ** ERC-20 Metadata **

  function name() public view virtual returns (string memory) {
    return getComplianceTokenStorage().tokenName;
  }

  function symbol() public view virtual returns (string memory) {
    return getComplianceTokenStorage().tokenSymbol;
  }

  function decimals() public view virtual returns (uint8) {
    return getComplianceTokenStorage().tokenDecimals;
  }

  // ** End ERC-20 Metadata **

  // ** ERC-7943 Methods **

  /// @inheritdoc IERC7943Fungible
  function canTransfer(
    address from,
    address to,
    uint256 amount
  )
    public
    view
    virtual
    override
    returns (bool allowed)
  {
    uint256 fromBalance = balanceOf(from);
    uint256 frozenAmount = getFrozenTokens(from);

    // Check if balance is sufficient
    if (fromBalance < frozenAmount) return false;
    // Check if amount exceeds unfrozen balance
    if (amount > fromBalance - frozenAmount) return false;
    // Check if both parties can transact (whitelist check)
    if (!canTransact(from) || !canTransact(to)) return false;

    return true;
  }

  /// @inheritdoc IERC7943Fungible
  function canTransact(address account) public view virtual override returns (bool allowed) {
    return getComplianceTokenStorage().whitelist[account];
  }

  /// @inheritdoc IERC7943Fungible
  function getFrozenTokens(address account) public view virtual override returns (uint256 amount) {
    return getComplianceTokenStorage().frozenTokens[account];
  }

  /// @inheritdoc IERC7943Fungible
  function setFrozenTokens(address account, uint256 amount) public virtual override runPolicy returns (bool result) {
    getComplianceTokenStorage().frozenTokens[account] = amount;
    emit Frozen(account, amount);
    return true;
  }

  /// @inheritdoc IERC7943Fungible
  /// @dev This implementation:
  /// - Requires the recipient to be whitelisted (canTransact check)
  /// - Automatically unfreezes tokens if the transfer amount exceeds the unfrozen balance
  /// - Emits both Transfer and ForcedTransfer events
  function forcedTransfer(
    address from,
    address to,
    uint256 amount
  )
    public
    virtual
    override
    runPolicy
    returns (bool result)
  {
    require(from != address(0), "ERC7943: force transfer from the zero address");
    require(to != address(0), "ERC7943: force transfer to the zero address");
    require(canTransact(to), "ERC7943: recipient not whitelisted");

    // Handle frozen tokens - unfreeze if necessary
    _excessFrozenUpdate(from, amount);

    // Perform the transfer
    _update(from, to, amount);
    emit ForcedTransfer(from, to, amount);

    return true;
  }

  // ** End ERC-7943 Methods **

  // ** Whitelist Management **

  /**
   * @notice Updates the whitelist status for a given account.
   * @dev Policy-protected. Emits a {Whitelisted} event upon successful update.
   * @param account The address whose whitelist status is to be changed.
   * @param status The new whitelist status (true = whitelisted, false = not whitelisted).
   */
  function changeWhitelist(address account, bool status) external virtual runPolicy {
    getComplianceTokenStorage().whitelist[account] = status;
    emit Whitelisted(account, status);
  }

  // ** End Whitelist Management **

  // ** Mint/Burn Methods **

  /**
   * @notice Creates `amount` new tokens and assigns them to `to`.
   * @dev Policy-protected. Requires `to` to be whitelisted (canTransact check).
   *      Emits a {Transfer} event with `from` set to the zero address.
   * @param to The address that will receive the minted tokens.
   * @param amount The amount of tokens to mint.
   */
  function mint(address to, uint256 amount) public virtual runPolicy {
    require(canTransact(to), "ERC7943: mint to non-whitelisted address");
    _mint(to, amount);
  }

  /**
   * @notice Destroys `amount` tokens from the caller's account.
   * @dev Policy-protected. Requires sufficient unfrozen balance.
   *      Emits a {Transfer} event with `to` set to the zero address.
   * @param amount The amount of tokens to burn.
   */
  function burn(uint256 amount) public virtual runPolicy {
    _burn(msg.sender, amount);
  }

  /**
   * @notice Destroys `amount` tokens from a specified account.
   * @dev Policy-protected. Automatically unfreezes tokens if necessary.
   *      This is an administrative burn that can burn frozen tokens.
   *      Emits a {Transfer} event with `to` set to the zero address.
   * @param from The address to burn tokens from.
   * @param amount The amount of tokens to burn.
   */
  function burnFrom(address from, uint256 amount) public virtual runPolicy {
    // Handle frozen tokens - unfreeze if necessary (administrative action)
    _excessFrozenUpdate(from, amount);
    _burn(from, amount);
  }

  // ** End Mint/Burn Methods **

  function getCCIPAdmin() public view virtual returns (address) {
    return owner();
  }

  /// @inheritdoc IERC165
  function supportsInterface(bytes4 interfaceId) public view virtual override(PolicyProtected, IERC165) returns (bool) {
    return interfaceId == type(IERC7943Fungible).interfaceId || interfaceId == type(IERC20).interfaceId
      || super.supportsInterface(interfaceId);
  }

  // ** Internal Functions **

  function _transfer(address from, address to, uint256 amount) internal {
    require(from != address(0), "ERC20: transfer from the zero address");
    require(to != address(0), "ERC20: transfer to the zero address");

    // ERC-7943 compliance checks
    require(canTransact(from), "ERC7943: sender not whitelisted");
    require(canTransact(to), "ERC7943: recipient not whitelisted");
    _checkFrozenBalance(from, amount);

    _update(from, to, amount);
  }

  function _approve(address owner, address spender, uint256 amount, bool emitEvent) internal {
    require(owner != address(0), "ERC20: approve owner the zero address");
    require(spender != address(0), "ERC20: approve spender the zero address");

    getComplianceTokenStorage().allowances[owner][spender] = amount;
    if (emitEvent) {
      emit Approval(owner, spender, amount);
    }
  }

  function _spendAllowance(address owner, address spender, uint256 amount) internal {
    uint256 currentAllowance = allowance(owner, spender);
    if (currentAllowance != type(uint256).max) {
      require(currentAllowance >= amount, "ERC20: transfer amount exceeds allowance");
      unchecked {
        _approve(owner, spender, currentAllowance - amount, false);
      }
    }
  }

  /**
   * @notice Checks if an account has sufficient unfrozen balance for an operation.
   * @param account The account to check
   * @param amount The amount needed for the operation
   */
  function _checkFrozenBalance(address account, uint256 amount) internal view {
    uint256 balance = balanceOf(account);
    uint256 frozen = getFrozenTokens(account);
    uint256 unfrozen = balance > frozen ? balance - frozen : 0;
    require(amount <= unfrozen, "ERC7943: amount exceeds unfrozen balance");
  }

  /**
   * @notice Updates frozen token amount when a forced transfer or burn exceeds the unfrozen balance.
   * @dev Reduces the frozen token amount to ensure consistency. Emits {Frozen} when amount is reduced.
   * @param account The address whose frozen tokens may need adjustment.
   * @param amount The amount being forcibly transferred or burned.
   */
  function _excessFrozenUpdate(address account, uint256 amount) internal {
    uint256 balance = balanceOf(account);
    uint256 frozen = getFrozenTokens(account);
    uint256 unfrozen = balance > frozen ? balance - frozen : 0;

    if (amount > unfrozen && amount <= balance) {
      uint256 newFrozen = frozen - (amount - unfrozen);
      getComplianceTokenStorage().frozenTokens[account] = newFrozen;
      emit Frozen(account, newFrozen);
    }
  }

  function _mint(address to, uint256 amount) internal {
    require(to != address(0), "ERC20: mint to the zero address");
    _update(address(0), to, amount);
  }

  function _burn(address from, uint256 amount) internal {
    require(from != address(0), "ERC20: burn from the zero address");

    ComplianceTokenStorage storage $ = getComplianceTokenStorage();
    uint256 fromBalance = $.balances[from];
    require(fromBalance >= amount, "ERC20: burn amount exceeds balance");

    _update(from, address(0), amount);
  }

  function _update(address from, address to, uint256 amount) internal virtual {
    ComplianceTokenStorage storage $ = getComplianceTokenStorage();

    if (from == address(0)) {
      // Mint: increase total supply
      $.totalSupply += amount;
    } else {
      uint256 fromBalance = $.balances[from];
      require(fromBalance >= amount, "ERC20: transfer amount exceeds balance");
      unchecked {
        $.balances[from] = fromBalance - amount;
      }
    }

    if (to == address(0)) {
      // Burn: decrease total supply
      unchecked {
        $.totalSupply -= amount;
      }
    } else {
      unchecked {
        $.balances[to] += amount;
      }
    }

    emit Transfer(from, to, amount);
  }
}
