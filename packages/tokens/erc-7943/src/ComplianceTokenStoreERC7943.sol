// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

contract ComplianceTokenStoreERC7943 {
  /// @custom:storage-location erc7201:compliance-token-erc7943.ComplianceTokenStoreERC7943
  struct ComplianceTokenStorage {
    string tokenName;
    string tokenSymbol;
    uint8 tokenDecimals;
    uint256 totalSupply;
    mapping(address account => uint256 balance) balances;
    mapping(address account => mapping(address spender => uint256 allowance)) allowances;
    mapping(address account => uint256 amount) frozenTokens;
    mapping(address account => bool allowed) sendWhitelist;
    mapping(address account => bool allowed) receiveWhitelist;
  }

  // keccak256(abi.encode(uint256(keccak256("compliance-token-erc7943.ComplianceTokenStoreERC7943")) - 1)) &
  // ~bytes32(uint256(0xff))
  // solhint-disable-next-line const-name-snakecase
  bytes32 private constant complianceTokenStorageLocation =
    0x8b1f1c4e2a7d3b9f6c5e4d3a2b1c0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b00;

  function getComplianceTokenStorage() internal pure returns (ComplianceTokenStorage storage $) {
    // solhint-disable-next-line no-inline-assembly
    assembly {
      $.slot := complianceTokenStorageLocation
    }
  }
}
