// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ComplianceTokenStoreERC20} from "./ComplianceTokenStoreERC20.sol";
import {PolicyProtected} from "@chainlink/policy-management/core/PolicyProtected.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

/**
 * @title ComplianceTokenERC20
 * @notice A policy-protected ERC-20 compliant token with strict frozen token preservation.
 *
 * @dev This implementation enforces a strict separation between frozen and free balances:
 *
 * **Frozen Token Behavior:**
 * - Frozen tokens remain immutably frozen during all operations
 * - All operations (transfers, burns, etc.) require sufficient unfrozen balance
 * - No automatic unfreezing occurs - frozen status must be explicitly managed
 * - Supports "pre-freezing" tokens before they are received by an account
 *
 * **Balance Management:**
 * - Total Balance = Free Balance + Frozen Balance
 * - Available Balance = Total Balance - Frozen Balance
 * - Operations only proceed if Available Balance >= Required Amount
 *
 * **Key Features:**
 * - Maximum compliance control through explicit frozen token management
 * - Administrative functions (freeze/unfreeze) are policy-protected
 * - Force transfer capability for administrative operations
 * - Integration with policy engine for complex compliance rules
 *
 * @dev Note: Alternative implementations may handle frozen tokens differently,
 * such as automatically unfreezing tokens during operations for flexibility.
 */
contract ComplianceTokenERC20 is Initializable, PolicyProtected, ComplianceTokenStoreERC20, IERC20 {
  /**
   * @notice Emitted when a freeze has been placed on an account.
   * @param account The address of the account whose tokens were frozen.
   * @param amount The amount of tokens frozen.
   */
  event Frozen(address indexed account, uint256 amount);

  /**
   * @notice Emitted when a freeze has been removed on an account.
   * @param account The address of the account whose tokens were unfrozen.
   * @param amount The amount of tokens unfrozen.
   */
  event Unfrozen(address indexed account, uint256 amount);

  /**
   * @notice Emitted when tokens are administratively transferred.
   * @param from The address whose token balance is being reduced.
   * @param to The address whose token balance is being increased.
   * @param amount The amount of tokens transferred.
   */
  event ForceTransfer(address indexed from, address indexed to, uint256 amount);

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
    __ComplianceTokenERC20_init(tokenName, tokenSymbol, tokenDecimals, policyEngine);
  }

  /**
   * @dev Upgradeable init function to be used by a token implementation contract.
   * @param tokenName The name of the token.
   * @param tokenSymbol The symbol of the token.
   * @param tokenDecimals The number of decimals to use for display purposes.
   * @param policyEngine The address of the policy engine contract.
   */
  function __ComplianceTokenERC20_init(
    string memory tokenName,
    string memory tokenSymbol,
    uint8 tokenDecimals,
    address policyEngine
  )
    internal
    onlyInitializing
  {
    __ComplianceTokenERC20_init_unchained(tokenName, tokenSymbol, tokenDecimals);
    __PolicyProtected_init(msg.sender, policyEngine);
  }

  /**
   * @dev Unchained upgradeable init function to be used by a token implementation contract.
   * @param tokenName The name of the token.
   * @param tokenSymbol The symbol of the token.
   * @param tokenDecimals The number of decimals to use for display purposes.
   */
  function __ComplianceTokenERC20_init_unchained(
    string memory tokenName,
    string memory tokenSymbol,
    uint8 tokenDecimals
  )
    internal
    onlyInitializing
  {
    ComplianceTokenStorage storage $ = getComplianceTokenStorage();
    $.name = tokenName;
    $.symbol = tokenSymbol;
    $.decimals = tokenDecimals;
  }

  // ** ERC-20 Methods **
  function totalSupply() public view virtual override returns (uint256) {
    return getComplianceTokenStorage().totalSupply;
  }

  function balanceOf(address account) public view virtual override returns (uint256) {
    return getComplianceTokenStorage().balances[account];
  }

  function transfer(address to, uint256 amount) public virtual override runPolicy returns (bool) {
    _transfer(msg.sender, to, amount);
    return true;
  }

  function allowance(address owner, address spender) public view virtual override returns (uint256) {
    return getComplianceTokenStorage().allowances[owner][spender];
  }

  function approve(address spender, uint256 amount) public virtual override runPolicy returns (bool) {
    _approve(msg.sender, spender, amount, true);
    return true;
  }

  function transferFrom(address from, address to, uint256 amount) public virtual override runPolicy returns (bool) {
    _spendAllowance(from, msg.sender, amount);
    _transfer(from, to, amount);
    return true;
  }

  // ** End ERC-20 Methods **

  function name() public view virtual returns (string memory) {
    return getComplianceTokenStorage().name;
  }

  function symbol() public view virtual returns (string memory) {
    return getComplianceTokenStorage().symbol;
  }

  function decimals() public view virtual returns (uint8) {
    return getComplianceTokenStorage().decimals;
  }

  function freeze(address account, uint256 amount, bytes calldata context) public virtual runPolicyWithContext(context) {
    getComplianceTokenStorage().frozenBalances[account] += amount;
    emit Frozen(account, amount);
  }

  function unfreeze(
    address account,
    uint256 amount,
    bytes calldata context
  )
    public
    virtual
    runPolicyWithContext(context)
  {
    require(getComplianceTokenStorage().frozenBalances[account] >= amount, "amount exceeds frozen balance");

    getComplianceTokenStorage().frozenBalances[account] -= amount;
    emit Unfrozen(account, amount);
  }

  function frozenBalanceOf(address account) public view virtual returns (uint256) {
    return getComplianceTokenStorage().frozenBalances[account];
  }

  /**
   * @notice Administratively transfers tokens between accounts.
   * @dev Performs a policy-protected transfer while preserving frozen token status.
   *
   * **Frozen Token Handling:**
   * - Frozen tokens remain frozen during the transfer
   * - Operation will revert if insufficient unfrozen balance exists
   * - Explicit unfreezing is required before transfer if needed
   *
   * This ensures administrative transfers maintain strict compliance with
   * frozen token restrictions.
   *
   * @param from The address whose token balance is being reduced
   * @param to The address whose token balance is being increased
   * @param amount The amount of tokens to transfer
   * @param context Additional context for policy validation
   */
  function forceTransfer(
    address from,
    address to,
    uint256 amount,
    bytes calldata context
  )
    public
    virtual
    runPolicyWithContext(context)
  {
    require(from != address(0), "transfer from the zero address");
    require(to != address(0), "transfer to the zero address");

    _update(from, to, amount);
    emit ForceTransfer(from, to, amount);
  }

  function mint(address to, uint256 amount) public virtual runPolicy {
    _mint(to, amount);
  }

  function burn(uint256 amount) public virtual runPolicy {
    _burn(msg.sender, amount);
  }

  function burnFrom(address from, uint256 amount) public virtual runPolicy {
    _burn(from, amount);
  }

  function getCCIPAdmin() public view virtual returns (address) {
    return owner();
  }

  function supportsInterface(bytes4 interfaceId) public view virtual override(PolicyProtected) returns (bool) {
    return super.supportsInterface(interfaceId);
  }

  function _transfer(address from, address to, uint256 amount) internal {
    require(from != address(0), "ERC20: transfer from the zero address");
    require(to != address(0), "ERC20: transfer to the zero address");

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
   * @dev Enforces strict frozen token preservation by ensuring operations only
   * use available (unfrozen) tokens:
   *
   * **Calculation:** `availableBalance = totalBalance - frozenBalance`
   *
   * The operation is allowed only if `availableBalance >= amount`.
   * Frozen tokens remain frozen and cannot be used for any operations.
   *
   * @param account The account to check
   * @param amount The amount needed for the operation
   */
  function _checkFrozenBalance(address account, uint256 amount) internal view {
    require(
      getComplianceTokenStorage().balances[account] >= amount + getComplianceTokenStorage().frozenBalances[account],
      "amount exceeds available balance"
    );
  }

  function _mint(address to, uint256 amount) internal {
    require(to != address(0), "ERC20: mint to the zero address");

    _update(address(0), to, amount);
  }

  /**
   * @notice Burns tokens from an account.
   * @dev Destroys tokens while preserving frozen token status.
   *
   * **Frozen Token Handling:**
   * - Frozen tokens remain frozen during the burn operation
   * - Operation will revert if insufficient unfrozen balance exists
   * - Explicit unfreezing is required before burning if needed
   *
   * This ensures burn operations maintain strict compliance with
   * frozen token restrictions, only destroying genuinely available tokens.
   *
   * @param from The address to burn tokens from
   * @param amount The amount of tokens to burn
   */
  function _burn(address from, uint256 amount) internal {
    require(from != address(0), "ERC20: burn from the zero address");

    _checkFrozenBalance(from, amount);
    _update(from, address(0), amount);
  }

  function _update(address from, address to, uint256 amount) internal virtual {
    ComplianceTokenStorage storage $ = getComplianceTokenStorage();
    if (from == address(0)) {
      // Overflow check required: The rest of the code assumes that totalSupply never overflows
      $.totalSupply += amount;
    } else {
      uint256 fromBalance = $.balances[from];
      if (fromBalance < amount) {
        revert("ERC20: transfer amount exceeds balance");
      }
      unchecked {
        // Overflow not possible: amount <= fromBalance <= totalSupply.
        $.balances[from] = fromBalance - amount;
      }
    }

    if (to == address(0)) {
      unchecked {
        // Overflow not possible: amount <= totalSupply or amount <= fromBalance <= totalSupply.
        $.totalSupply -= amount;
      }
    } else {
      unchecked {
        // Overflow not possible: balance + amount is at most totalSupply, which we know fits into a uint256.
        $.balances[to] += amount;
      }
    }

    emit Transfer(from, to, amount);
  }
}
