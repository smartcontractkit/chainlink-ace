// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

contract ComplianceTokenStoreERC3643 {
  /// @custom:storage-location erc7201:compliance-token-erc20.ComplianceTokenStoreERC3643
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

  // keccak256(abi.encode(uint256(keccak256("compliance-token-erc20.ComplianceTokenStoreERC3643")) - 1)) &
  // ~bytes32(uint256(0xff))
  // solhint-disable-next-line const-name-snakecase
  bytes32 private constant complianceTokenStorageLocation =
    0xb812bfd341d808811ca5cb8ca1c12a45441244343a7b7b1ef61042686f756b00;

  function getComplianceTokenStorage() internal pure returns (ComplianceTokenStorage storage $) {
    // solhint-disable-next-line no-inline-assembly
    assembly {
      $.slot := complianceTokenStorageLocation
    }
  }
}
