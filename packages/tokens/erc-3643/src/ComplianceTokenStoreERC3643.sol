// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

contract ComplianceTokenStoreERC3643 {
  /// @custom:storage-location erc7201:compliance-token-erc3643.ComplianceTokenStoreERC3643
  struct ComplianceTokenStorage {
    string tokenName;
    string tokenSymbol;
    uint8 tokenDecimals;
    bool tokenPaused;
    uint256 totalSupply;
    mapping(address userAddress => uint256 balance) balances;
    mapping(address userAddress => mapping(address spender => uint256 allowance)) allowances;
    mapping(address userAddress => bool isFrozen) frozen;
    mapping(address userAddress => uint256 amount) frozenTokens;
  }

  // keccak256(abi.encode(uint256(keccak256("compliance-token-erc3643.ComplianceTokenStoreERC3643")) - 1)) &
  // ~bytes32(uint256(0xff))
  // solhint-disable-next-line const-name-snakecase
  bytes32 private constant complianceTokenStorageLocation =
    0xdc918d90baf191b8d972d59f66f8d1c2691d3df52961983ba712e24ad9fcd600;

  function getComplianceTokenStorage() internal pure returns (ComplianceTokenStorage storage $) {
    // solhint-disable-next-line no-inline-assembly
    assembly {
      $.slot := complianceTokenStorageLocation
    }
  }
}
