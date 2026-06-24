// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {IAdvancedPoolHooks} from "@chainlink/contracts-ccip/interfaces/IAdvancedPoolHooks.sol";
import {IPolicyEngine} from "../../src/interfaces/IPolicyEngine.sol";
import {Client} from "@chainlink/contracts-ccip/libraries/Client.sol";
import {MessageV1Codec} from "@chainlink/contracts-ccip/libraries/MessageV1Codec.sol";
import {Pool} from "@chainlink/contracts-ccip/libraries/Pool.sol";
import {OffRamp} from "@chainlink/contracts-ccip/offRamp/OffRamp.sol";
import {Router} from "@chainlink/contracts-ccip/Router.sol";
import {AdvancedPoolHooksE2ESetup} from "./PoolHooksE2ESetup.t.sol";
import {OffRampHelper} from "@chainlink/contracts-ccip/test/helpers/OffRampHelper.sol";

import {VmSafe} from "forge-std/Vm.sol";

contract AdvancedPoolHooksE2E_DestChain is AdvancedPoolHooksE2ESetup {
  OffRampHelper internal s_offRamp;

  function setUp() public virtual override {
    super.setUp();

    s_offRamp = new OffRampHelper(
      OffRamp.StaticConfig({
        localChainSelector: DEST_CHAIN_SELECTOR,
        gasForCallExactCheck: GAS_FOR_CALL_EXACT_CHECK,
        rmnRemote: s_mockRMNRemote,
        tokenAdminRegistry: address(s_tokenAdminRegistry),
        maxGasBufferToUpdateState: DEFAULT_MAX_GAS_BUFFER_TO_UPDATE_STATE
      })
    );

    bytes[] memory onRamps = new bytes[](1);
    onRamps[0] = abi.encode(s_onRamp);
    OffRamp.SourceChainConfigArgs[] memory sourceChainConfigs = new OffRamp.SourceChainConfigArgs[](1);
    sourceChainConfigs[0] = OffRamp.SourceChainConfigArgs({
      router: s_destRouter,
      sourceChainSelector: SOURCE_CHAIN_SELECTOR,
      isEnabled: true,
      onRamps: onRamps,
      defaultCCVs: _defaultCCVs(),
      laneMandatedCCVs: new address[](0)
    });
    s_offRamp.applySourceChainConfigUpdates(sourceChainConfigs);

    Router.OffRamp[] memory offRampUpdates = new Router.OffRamp[](1);
    offRampUpdates[0] = Router.OffRamp({sourceChainSelector: SOURCE_CHAIN_SELECTOR, offRamp: address(s_offRamp)});
    s_destRouter.applyRampUpdates(new Router.OnRamp[](0), new Router.OffRamp[](0), offRampUpdates);

    s_burnMintPool.setDynamicConfig(address(s_destRouter), address(0), address(0));
  }

  function _defaultCCVs() internal view returns (address[] memory) {
    address[] memory ccvs = new address[](1);
    ccvs[0] = s_defaultCCV;
    return ccvs;
  }

  function _buildTokenTransfer(
    address receiver,
    uint256 amount
  )
    internal
    view
    returns (MessageV1Codec.TokenTransferV1 memory)
  {
    return MessageV1Codec.TokenTransferV1({
      amount: amount,
      sourcePoolAddress: abi.encode(address(s_burnMintPool)),
      sourceTokenAddress: abi.encode(address(s_aceToken)),
      destTokenAddress: abi.encodePacked(address(s_aceToken)),
      tokenReceiver: abi.encodePacked(receiver),
      extraData: abi.encode(uint256(18))
    });
  }

  function _expectedPostflightPolicyRevertData(address receiver, uint256 amount) internal view returns (bytes memory) {
    uint256 localAmount = amount;
    uint16 blockConfirmationRequested = 0;

    bytes memory originalSender = abi.encode(OWNER);
    bytes memory sourcePoolAddress = abi.encode(address(s_burnMintPool));
    bytes memory sourcePoolData = abi.encode(uint256(18));
    bytes memory offchainTokenData = "";

    Pool.ReleaseOrMintInV1 memory releaseOrMintIn = Pool.ReleaseOrMintInV1({
      originalSender: originalSender,
      remoteChainSelector: SOURCE_CHAIN_SELECTOR,
      receiver: receiver,
      sourceDenominatedAmount: amount,
      localToken: address(s_aceToken),
      sourcePoolAddress: sourcePoolAddress,
      sourcePoolData: sourcePoolData,
      offchainTokenData: offchainTokenData
    });

    bytes memory payloadData = abi.encode(releaseOrMintIn, localAmount, blockConfirmationRequested);

    IPolicyEngine.Payload memory payload = IPolicyEngine.Payload({
      selector: IAdvancedPoolHooks.postflightCheck.selector,
      sender: address(s_burnMintPool),
      data: payloadData,
      context: offchainTokenData
    });

    // OffRamp wraps downstream errors from pools as TokenHandlingError(localToken, err).
    bytes memory innerErr = abi.encodeWithSelector(
      IPolicyEngine.PolicyRunRejected.selector, address(s_volumePolicy), VOLUME_POLICY_REJECT_REASON, payload
    );
    return abi.encodeWithSelector(OffRamp.TokenHandlingError.selector, address(s_aceToken), innerErr);
  }

  /// @notice Validates the complete dest chain flow: OffRamp -> BurnMintTokenPool -> AdvancedPoolHooks
  /// -> PolicyEngine -> AdvancedPoolHooksExtractor -> VolumePolicy.
  function test_destChain_releaseOrMint_policyAccepted() public {
    uint256 receiverBalanceBefore = s_aceToken.balanceOf(s_receiver);

    MessageV1Codec.TokenTransferV1 memory tokenTransfer = _buildTokenTransfer(s_receiver, VALID_AMOUNT);

    vm.recordLogs();

    (Client.EVMTokenAmount memory destTokenAmount,) =
      s_offRamp.releaseOrMintSingleToken(tokenTransfer, abi.encode(OWNER), SOURCE_CHAIN_SELECTOR, 0);

    uint256 receiverBalanceAfter = s_aceToken.balanceOf(s_receiver);
    assertEq(VALID_AMOUNT, receiverBalanceAfter - receiverBalanceBefore, "Receiver should receive minted tokens");
    assertEq(VALID_AMOUNT, destTokenAmount.amount, "Returned amount should match");
    assertEq(address(s_aceToken), destTokenAmount.token, "Returned token should match");

    // Verify PolicyRunComplete event
    VmSafe.Log[] memory logs = vm.getRecordedLogs();
    bytes32 policyRunCompleteTopic = IPolicyEngine.PolicyRunComplete.selector;

    bool foundEvent = false;
    for (uint256 i = 0; i < logs.length; i++) {
      if (
        logs[i].emitter == address(s_policyEngine) && logs[i].topics.length > 0
          && logs[i].topics[0] == policyRunCompleteTopic
      ) {
        foundEvent = true;

        assertEq(address(s_burnMintPool), address(uint160(uint256(logs[i].topics[1]))));
        assertEq(address(s_advancedPoolHooks), address(uint160(uint256(logs[i].topics[2]))));
        assertEq(IAdvancedPoolHooks.postflightCheck.selector, bytes4(logs[i].topics[3]));

        (IPolicyEngine.Parameter[] memory params,) = abi.decode(logs[i].data, (IPolicyEngine.Parameter[], bytes));
        assertEq(9, params.length, "Should have 9 postflight parameters");

        // PARAM_FROM = originalSender
        assertEq(s_extractor.PARAM_FROM(), params[0].name);
        assertEq(abi.encode(OWNER), params[0].value);

        // PARAM_TO = receiver
        assertEq(s_extractor.PARAM_TO(), params[1].name);
        assertEq(s_receiver, abi.decode(params[1].value, (address)));

        // PARAM_AMOUNT = localAmount
        assertEq(s_extractor.PARAM_AMOUNT(), params[2].name);
        assertEq(VALID_AMOUNT, abi.decode(params[2].value, (uint256)));

        // PARAM_REMOTE_CHAIN_SELECTOR = SOURCE_CHAIN_SELECTOR
        assertEq(s_extractor.PARAM_REMOTE_CHAIN_SELECTOR(), params[3].name);
        assertEq(SOURCE_CHAIN_SELECTOR, abi.decode(params[3].value, (uint64)));

        // PARAM_TOKEN = local token
        assertEq(s_extractor.PARAM_TOKEN(), params[4].name);
        assertEq(address(s_aceToken), abi.decode(params[4].value, (address)));

        // PARAM_BLOCK_CONFIRMATION_REQUESTED = 0
        assertEq(s_extractor.PARAM_BLOCK_CONFIRMATION_REQUESTED(), params[5].name);
        assertEq(uint16(0), abi.decode(params[5].value, (uint16)));

        // PARAM_SOURCE_POOL_ADDRESS
        assertEq(s_extractor.PARAM_SOURCE_POOL_ADDRESS(), params[6].name);
        assertEq(abi.encode(address(s_burnMintPool)), params[6].value);

        // PARAM_SOURCE_POOL_DATA = source decimals
        assertEq(s_extractor.PARAM_SOURCE_POOL_DATA(), params[7].name);
        assertEq(uint256(18), abi.decode(params[7].value, (uint256)));

        // PARAM_SOURCE_DENOMINATED_AMOUNT
        assertEq(s_extractor.PARAM_SOURCE_DENOMINATED_AMOUNT(), params[8].name);
        assertEq(VALID_AMOUNT, abi.decode(params[8].value, (uint256)));

        break;
      }
    }

    assertTrue(foundEvent, "PolicyRunComplete event should be emitted");
  }

  // Reverts

  function test_destChain_releaseOrMint_RevertWhen_AmountExceedsMax() public {
    MessageV1Codec.TokenTransferV1 memory tokenTransfer = _buildTokenTransfer(s_receiver, TOO_HIGH_AMOUNT);

    vm.expectRevert(_expectedPostflightPolicyRevertData(s_receiver, TOO_HIGH_AMOUNT));
    s_offRamp.releaseOrMintSingleToken(tokenTransfer, abi.encode(OWNER), SOURCE_CHAIN_SELECTOR, 0);
  }

  function test_destChain_releaseOrMint_RevertWhen_AmountBelowMin() public {
    MessageV1Codec.TokenTransferV1 memory tokenTransfer = _buildTokenTransfer(s_receiver, TOO_LOW_AMOUNT);

    vm.expectRevert(_expectedPostflightPolicyRevertData(s_receiver, TOO_LOW_AMOUNT));
    s_offRamp.releaseOrMintSingleToken(tokenTransfer, abi.encode(OWNER), SOURCE_CHAIN_SELECTOR, 0);
  }
}
