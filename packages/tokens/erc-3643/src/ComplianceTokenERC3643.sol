// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IToken} from "../../../vendor/erc-3643/token/IToken.sol";
import {IIdentityRegistry} from "../../../vendor/erc-3643/registry/interface/IIdentityRegistry.sol";
import {IModularCompliance} from "../../../vendor/erc-3643/compliance/modular/IModularCompliance.sol";
import {ComplianceTokenStoreERC3643} from "./ComplianceTokenStoreERC3643.sol";
import {PolicyProtected} from "@chainlink/policy-management/core/PolicyProtected.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract ComplianceTokenERC3643 is Initializable, PolicyProtected, ComplianceTokenStoreERC3643, IToken {
  string private constant TOKEN_VERSION = "1.0.0";

  /// modifiers

  /// @dev Modifier to make a function callable only when the contract is not paused.
  modifier whenNotPaused() {
    require(!getComplianceTokenStorage().tokenPaused, "Pausable: paused");
    _;
  }

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
    __ComplianceTokenERC3643_init(tokenName, tokenSymbol, tokenDecimals, policyEngine);
  }

  /**
   * @dev Upgradeable init function to be used by a token implementation contract.
   * @param tokenName The name of the token.
   * @param tokenSymbol The symbol of the token.
   * @param tokenDecimals The number of decimals to use for display purposes.
   * @param policyEngine The address of the policy engine contract.
   */
  function __ComplianceTokenERC3643_init(
    string memory tokenName,
    string memory tokenSymbol,
    uint8 tokenDecimals,
    address policyEngine
  )
    internal
    onlyInitializing
  {
    __PolicyProtected_init(msg.sender, policyEngine);
    __ComplianceTokenERC3643_init_unchained(tokenName, tokenSymbol, tokenDecimals);
  }

  /**
   * @dev Unchained upgradeable init function to be used by a token implementation contract.
   * @param tokenName The name of the token.
   * @param tokenSymbol The symbol of the token.
   * @param tokenDecimals The number of decimals to use for display purposes.
   */
  function __ComplianceTokenERC3643_init_unchained(
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

  /**
   *  @dev See {IERC20-approve}.
   */
  function approve(address _spender, uint256 _amount) external virtual override whenNotPaused runPolicy returns (bool) {
    _approve(msg.sender, _spender, _amount);
    return true;
  }

  /**
   *  @dev Increases the allowance granted to `_spender` by the caller.
   *  This is an OpenZeppelin extension to ERC20, not part of the core ERC20 standard.
   */
  function increaseAllowance(
    address _spender,
    uint256 _addedValue
  )
    external
    virtual
    whenNotPaused
    runPolicy
    returns (bool)
  {
    _approve(msg.sender, _spender, getComplianceTokenStorage().allowances[msg.sender][_spender] + (_addedValue));
    return true;
  }

  /**
   *  @dev Decreases the allowance granted to `_spender` by the caller.
   *  This is an OpenZeppelin extension to ERC20, not part of the core ERC20 standard.
   */
  function decreaseAllowance(
    address _spender,
    uint256 _subtractedValue
  )
    external
    virtual
    whenNotPaused
    runPolicy
    returns (bool)
  {
    _approve(msg.sender, _spender, getComplianceTokenStorage().allowances[msg.sender][_spender] - _subtractedValue);
    return true;
  }

  /**
   *  @dev See {IToken-setName}.
   */
  function setName(string calldata _name) external override runPolicy {
    require(keccak256(abi.encode(_name)) != keccak256(abi.encode("")), "invalid argument - empty string");
    ComplianceTokenStorage storage $ = getComplianceTokenStorage();
    $.tokenName = _name;
    emit UpdatedTokenInformation($.tokenName, $.tokenSymbol, $.tokenDecimals, TOKEN_VERSION, address(0));
  }

  /**
   *  @dev See {IToken-setSymbol}.
   */
  function setSymbol(string calldata _symbol) external override runPolicy {
    require(keccak256(abi.encode(_symbol)) != keccak256(abi.encode("")), "invalid argument - empty string");
    ComplianceTokenStorage storage $ = getComplianceTokenStorage();
    $.tokenSymbol = _symbol;
    emit UpdatedTokenInformation($.tokenName, $.tokenSymbol, $.tokenDecimals, TOKEN_VERSION, address(0));
  }

  /**
   *  @dev See {IToken-setOnchainID}.
   *  if _onchainID is set at zero address it means no ONCHAINID is bound to this token
   */
  function setOnchainID(address /*_onchainID*/ ) external pure override {
    revert("Not implemented");
  }

  /**
   *  @dev See {IToken-pause}.
   */
  function pause() external override runPolicy {
    getComplianceTokenStorage().tokenPaused = true;
    emit Paused(msg.sender);
  }

  /**
   *  @dev See {IToken-unpause}.
   */
  function unpause() external override runPolicy {
    getComplianceTokenStorage().tokenPaused = false;
    emit Unpaused(msg.sender);
  }

  /**
   *  @dev See {IToken-batchTransfer}.
   */
  function batchTransfer(address[] calldata _toList, uint256[] calldata _amounts) external override {
    for (uint256 i = 0; i < _toList.length; i++) {
      transfer(_toList[i], _amounts[i]);
    }
  }

  /**
   *  @notice ERC-20 overridden function that include logic to check for trade validity.
   *  Require that the from and to addresses are not frozen.
   *  Require that the value should not exceed available balance .
   *  Require that the to address is a verified address
   *  Skips emitting an {Approval} event indicating an allowance update.
   *  @param _from The address of the sender
   *  @param _to The address of the receiver
   *  @param _amount The number of tokens to transfer
   *  @return `true` if successful and revert if unsuccessful
   */
  function transferFrom(
    address _from,
    address _to,
    uint256 _amount
  )
    external
    override
    whenNotPaused
    runPolicy
    returns (bool)
  {
    ComplianceTokenStorage storage $ = getComplianceTokenStorage();

    require(!$.frozen[_to] && !$.frozen[_from], "wallet is frozen");
    require(_amount <= $.balances[_from] - ($.frozenTokens[_from]), "Insufficient Balance");
    _approve(_from, msg.sender, $.allowances[_from][msg.sender] - (_amount), false);
    _transfer(_from, _to, _amount);
    return true;
  }

  /**
   *  @dev See {IToken-batchForcedTransfer}.
   */
  function batchForcedTransfer(
    address[] calldata _fromList,
    address[] calldata _toList,
    uint256[] calldata _amounts
  )
    external
    override
  {
    for (uint256 i = 0; i < _fromList.length; i++) {
      forcedTransfer(_fromList[i], _toList[i], _amounts[i]);
    }
  }

  /**
   *  @dev See {IToken-batchMint}.
   */
  function batchMint(address[] calldata _toList, uint256[] calldata _amounts) external override {
    for (uint256 i = 0; i < _toList.length; i++) {
      mint(_toList[i], _amounts[i]);
    }
  }

  /**
   *  @dev See {IToken-batchBurn}.
   */
  function batchBurn(address[] calldata _userAddresses, uint256[] calldata _amounts) external override {
    for (uint256 i = 0; i < _userAddresses.length; i++) {
      burn(_userAddresses[i], _amounts[i]);
    }
  }

  /**
   *  @dev See {IToken-batchSetAddressFrozen}.
   */
  function batchSetAddressFrozen(address[] calldata _userAddresses, bool[] calldata _freeze) external override {
    for (uint256 i = 0; i < _userAddresses.length; i++) {
      setAddressFrozen(_userAddresses[i], _freeze[i]);
    }
  }

  /**
   *  @dev See {IToken-batchFreezePartialTokens}.
   */
  function batchFreezePartialTokens(address[] calldata _userAddresses, uint256[] calldata _amounts) external override {
    for (uint256 i = 0; i < _userAddresses.length; i++) {
      freezePartialTokens(_userAddresses[i], _amounts[i]);
    }
  }

  /**
   *  @dev See {IToken-batchUnfreezePartialTokens}.
   */
  function batchUnfreezePartialTokens(address[] calldata _userAddresses, uint256[] calldata _amounts) external override {
    for (uint256 i = 0; i < _userAddresses.length; i++) {
      unfreezePartialTokens(_userAddresses[i], _amounts[i]);
    }
  }

  /**
   *  @dev See {IToken-recoveryAddress}.
   */
  function recoveryAddress(
    address, /*_lostWallet */
    address, /*_newWallet */
    address /*_investorOnchainID */
  )
    external
    pure
    override
    returns (bool)
  {
    revert("Not implemented");
  }

  /**
   *  @dev See {IERC20-totalSupply}.
   */
  function totalSupply() external view override returns (uint256) {
    return getComplianceTokenStorage().totalSupply;
  }

  /**
   *  @dev See {IERC20-allowance}.
   */
  function allowance(address _owner, address _spender) external view virtual override returns (uint256) {
    return getComplianceTokenStorage().allowances[_owner][_spender];
  }

  /**
   *  @dev See {IToken-identityRegistry}.
   */
  function identityRegistry() external pure override returns (IIdentityRegistry) {
    return IIdentityRegistry(address(0));
  }

  /**
   *  @dev See {IToken-compliance}.
   */
  function compliance() external pure override returns (IModularCompliance) {
    return IModularCompliance(address(0));
  }

  /**
   *  @dev See {IToken-paused}.
   */
  function paused() external view override returns (bool) {
    return getComplianceTokenStorage().tokenPaused;
  }

  /**
   *  @dev See {IToken-isFrozen}.
   */
  function isFrozen(address _userAddress) external view override returns (bool) {
    return getComplianceTokenStorage().frozen[_userAddress];
  }

  /**
   *  @dev See {IToken-getFrozenTokens}.
   */
  function getFrozenTokens(address _userAddress) external view override returns (uint256) {
    return getComplianceTokenStorage().frozenTokens[_userAddress];
  }

  /**
   *  @dev See {IToken-decimals}.
   */
  function decimals() external view override returns (uint8) {
    return getComplianceTokenStorage().tokenDecimals;
  }

  /**
   *  @dev See {IToken-name}.
   */
  function name() external view override returns (string memory) {
    return getComplianceTokenStorage().tokenName;
  }

  /**
   *  @dev See {IToken-onchainID}.
   */
  function onchainID() external pure override returns (address) {
    return address(0);
  }

  /**
   *  @dev See {IToken-symbol}.
   */
  function symbol() external view override returns (string memory) {
    return getComplianceTokenStorage().tokenSymbol;
  }

  /**
   *  @dev See {IToken-version}.
   */
  function version() external pure override returns (string memory) {
    return TOKEN_VERSION;
  }

  /**
   *  @notice ERC-20 overridden function that include logic to check for trade validity.
   *  Require that the msg.sender and to addresses are not frozen.
   *  Require that the value should not exceed available balance .
   *  Require that the to address is a verified address
   *  @param _to The address of the receiver
   *  @param _amount The number of tokens to transfer
   *  @return `true` if successful and revert if unsuccessful
   */
  function transfer(address _to, uint256 _amount) public override whenNotPaused runPolicy returns (bool) {
    ComplianceTokenStorage storage $ = getComplianceTokenStorage();

    require(!$.frozen[_to] && !$.frozen[msg.sender], "wallet is frozen");
    require(_amount <= $.balances[msg.sender] - ($.frozenTokens[msg.sender]), "Insufficient Balance");
    _transfer(msg.sender, _to, _amount);
    return true;
  }

  /**
   *  @dev See {IToken-forcedTransfer}.
   */
  function forcedTransfer(address _from, address _to, uint256 _amount) public override runPolicy returns (bool) {
    ComplianceTokenStorage storage $ = getComplianceTokenStorage();

    require($.balances[_from] >= _amount, "sender balance too low");
    uint256 freeBalance = $.balances[_from] - ($.frozenTokens[_from]);
    if (_amount > freeBalance) {
      uint256 tokensToUnfreeze = _amount - (freeBalance);
      $.frozenTokens[_from] = $.frozenTokens[_from] - (tokensToUnfreeze);
      emit TokensUnfrozen(_from, tokensToUnfreeze);
    }
    _transfer(_from, _to, _amount);
    return true;
  }

  /**
   * @dev Mints tokens to a specified address as defined by the ERC-3643 IToken interface.
   */
  function mint(address _to, uint256 _amount) public override runPolicy {
    _mint(_to, _amount);
  }

  /**
   * @dev Burns tokens from a specified address as defined by the ERC-3643 IToken interface.
   */
  function burn(address _userAddress, uint256 _amount) public override runPolicy {
    ComplianceTokenStorage storage $ = getComplianceTokenStorage();

    require($.balances[_userAddress] >= _amount, "cannot burn more than balance");
    uint256 freeBalance = $.balances[_userAddress] - $.frozenTokens[_userAddress];
    if (_amount > freeBalance) {
      uint256 tokensToUnfreeze = _amount - (freeBalance);
      $.frozenTokens[_userAddress] = $.frozenTokens[_userAddress] - (tokensToUnfreeze);
      emit TokensUnfrozen(_userAddress, tokensToUnfreeze);
    }
    _burn(_userAddress, _amount);
  }

  /**
   *  @dev See {IToken-setAddressFrozen}.
   */
  function setAddressFrozen(address _userAddress, bool _freeze) public override runPolicy {
    ComplianceTokenStorage storage $ = getComplianceTokenStorage();

    $.frozen[_userAddress] = _freeze;
    emit AddressFrozen(_userAddress, _freeze, msg.sender);
  }

  /**
   *  @dev See {IToken-freezePartialTokens}.
   */
  function freezePartialTokens(address _userAddress, uint256 _amount) public override runPolicy {
    ComplianceTokenStorage storage $ = getComplianceTokenStorage();

    uint256 balance = $.balances[_userAddress];
    require(balance >= $.frozenTokens[_userAddress] + _amount, "Amount exceeds available balance");
    $.frozenTokens[_userAddress] = $.frozenTokens[_userAddress] + (_amount);
    emit TokensFrozen(_userAddress, _amount);
  }

  /**
   *  @dev See {IToken-unfreezePartialTokens}.
   */
  function unfreezePartialTokens(address _userAddress, uint256 _amount) public override runPolicy {
    ComplianceTokenStorage storage $ = getComplianceTokenStorage();

    require($.frozenTokens[_userAddress] >= _amount, "Amount should be less than or equal to frozen tokens");
    $.frozenTokens[_userAddress] = $.frozenTokens[_userAddress] - (_amount);
    emit TokensUnfrozen(_userAddress, _amount);
  }

  /**
   *  @dev See {IToken-setIdentityRegistry}.
   */
  function setIdentityRegistry(address /*_identityRegistry*/ ) public pure override {
    revert("Not implemented");
  }

  /**
   *  @dev See {IToken-setCompliance}.
   */
  function setCompliance(address /*_compliance*/ ) public pure override {
    revert("Not implemented");
  }

  /**
   *  @dev See {IERC20-balanceOf}.
   */
  function balanceOf(address _userAddress) public view override returns (uint256) {
    return getComplianceTokenStorage().balances[_userAddress];
  }

  function getCCIPAdmin() public view virtual returns (address) {
    return owner();
  }

  function supportsInterface(bytes4 interfaceId) public view virtual override(PolicyProtected) returns (bool) {
    return super.supportsInterface(interfaceId);
  }

  /**
   *  @dev See {ERC20-_transfer}.
   */
  function _transfer(address _from, address _to, uint256 _amount) internal virtual {
    require(_from != address(0), "ERC20: transfer from the zero address");
    require(_to != address(0), "ERC20: transfer to the zero address");

    ComplianceTokenStorage storage $ = getComplianceTokenStorage();

    _beforeTokenTransfer(_from, _to, _amount);

    $.balances[_from] = $.balances[_from] - _amount;
    $.balances[_to] = $.balances[_to] + _amount;
    emit Transfer(_from, _to, _amount);
  }

  /**
   *  @dev See {ERC20-_mint}.
   */
  function _mint(address _userAddress, uint256 _amount) internal virtual {
    require(_userAddress != address(0), "ERC20: mint to the zero address");

    ComplianceTokenStorage storage $ = getComplianceTokenStorage();

    _beforeTokenTransfer(address(0), _userAddress, _amount);

    $.totalSupply = $.totalSupply + _amount;
    $.balances[_userAddress] = $.balances[_userAddress] + _amount;
    emit Transfer(address(0), _userAddress, _amount);
  }

  /**
   *  @dev See {ERC20-_burn}.
   */
  function _burn(address _userAddress, uint256 _amount) internal virtual {
    require(_userAddress != address(0), "ERC20: burn from the zero address");

    ComplianceTokenStorage storage $ = getComplianceTokenStorage();

    _beforeTokenTransfer(_userAddress, address(0), _amount);

    $.balances[_userAddress] = $.balances[_userAddress] - _amount;
    $.totalSupply = $.totalSupply - _amount;
    emit Transfer(_userAddress, address(0), _amount);
  }

  /**
   *  @dev See {ERC20-_approve}.
   */
  function _approve(address _owner, address _spender, uint256 _amount) internal virtual {
    _approve(_owner, _spender, _amount, true);
  }

  /**
   *  @dev See {ERC20-_approve}.
   */
  function _approve(address _owner, address _spender, uint256 _amount, bool emitEvent) internal virtual {
    require(_owner != address(0), "ERC20: approve from the zero address");
    require(_spender != address(0), "ERC20: approve to the zero address");

    ComplianceTokenStorage storage $ = getComplianceTokenStorage();

    $.allowances[_owner][_spender] = _amount;
    if (emitEvent) {
      emit Approval(_owner, _spender, _amount);
    }
  }

  /**
   *  @dev See {ERC20-_beforeTokenTransfer}.
   */
  // solhint-disable-next-line no-empty-blocks
  function _beforeTokenTransfer(address _from, address _to, uint256 _amount) internal virtual {}
}
