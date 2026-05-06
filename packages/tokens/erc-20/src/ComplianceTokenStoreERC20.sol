// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

contract ComplianceTokenStoreERC20 {
  /// @custom:storage-location erc7201:chainlink.ace.ComplianceTokenStoreERC20
  struct ComplianceTokenStorage {
    string name;
    string symbol;
    uint8 decimals;
    uint256 totalSupply;
    mapping(address account => uint256 balance) balances;
    mapping(address account => mapping(address spender => uint256 allowance)) allowances;
    mapping(address account => uint256 amount) frozenBalances;
    mapping(bytes32 key => bytes data) data;
  }

  // keccak256(abi.encode(uint256(keccak256("chainlink.ace.ComplianceTokenStoreERC20")) - 1)) &
  // ~bytes32(uint256(0xff))
  // solhint-disable-next-line const-name-snakecase
  bytes32 private constant complianceTokenStorageLocation =
    0xf5303d81c67def4ec0b3a192701545f023de45401e43c238517d86c501b78900;

  function getComplianceTokenStorage() internal pure returns (ComplianceTokenStorage storage $) {
    // solhint-disable-next-line no-inline-assembly
    assembly {
      $.slot := complianceTokenStorageLocation
    }
  }
}
