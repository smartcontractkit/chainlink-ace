// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {IAdvancedPoolHooks} from "@chainlink/contracts-ccip/interfaces/IAdvancedPoolHooks.sol";
import {IPolicyEngine} from "../../src/interfaces/IPolicyEngine.sol";
import {Client} from "@chainlink/contracts-ccip/libraries/Client.sol";
import {Pool} from "@chainlink/contracts-ccip/libraries/Pool.sol";
import {Router} from "@chainlink/contracts-ccip/Router.sol";
import {AdvancedPoolHooksE2ESetup} from "./PoolHooksE2ESetup.t.sol";

import {IERC20} from "@openzeppelin/contracts@5.3.0/token/ERC20/IERC20.sol";
import {VmSafe} from "forge-std/Vm.sol";

contract AdvancedPoolHooksE2E_SourceChain is AdvancedPoolHooksE2ESetup {
  function setUp() public virtual override {
    super.setUp();

    Router.OnRamp[] memory onRampUpdates = new Router.OnRamp[](1);
    onRampUpdates[0] = Router.OnRamp({destChainSelector: DEST_CHAIN_SELECTOR, onRamp: address(s_onRamp)});
    s_sourceRouter.applyRampUpdates(onRampUpdates, new Router.OffRamp[](0), new Router.OffRamp[](0));

    deal(address(s_aceToken), OWNER, type(uint256).max);
    deal(s_sourceFeeToken, OWNER, type(uint256).max);
  }

  function _buildCCIPMessage(
    address receiver,
    uint256 tokenAmount
  )
    internal
    view
    returns (Client.EVM2AnyMessage memory)
  {
    Client.EVM2AnyMessage memory message = Client.EVM2AnyMessage({
      receiver: abi.encode(receiver),
      data: "",
      tokenAmounts: new Client.EVMTokenAmount[](1),
      feeToken: s_sourceFeeToken,
      extraArgs: ""
    });
    message.tokenAmounts[0] = Client.EVMTokenAmount({token: address(s_aceToken), amount: tokenAmount});
    return message;
  }

  function _buildAndApproveCcipSend(uint256 amount) internal returns (Client.EVM2AnyMessage memory) {
    Client.EVM2AnyMessage memory message = _buildCCIPMessage(s_receiver, amount);
    uint256 fee = s_sourceRouter.getFee(DEST_CHAIN_SELECTOR, message);
    IERC20(s_sourceFeeToken).approve(address(s_sourceRouter), fee);
    IERC20(address(s_aceToken)).approve(address(s_sourceRouter), amount);
    return message;
  }

  function _expectedPreflightPolicyRevertData(uint256 amount) internal view returns (bytes memory) {
    bytes memory tokenArgs = "";
    uint16 blockConfirmationRequested = 0;
    uint256 amountPostFee = amount;

    Pool.LockOrBurnInV1 memory lockOrBurnIn = Pool.LockOrBurnInV1({
      receiver: abi.encode(s_receiver),
      remoteChainSelector: DEST_CHAIN_SELECTOR,
      originalSender: OWNER,
      amount: amount,
      localToken: address(s_aceToken)
    });

    bytes memory payloadData = abi.encode(lockOrBurnIn, blockConfirmationRequested, tokenArgs, amountPostFee);

    IPolicyEngine.Payload memory payload = IPolicyEngine.Payload({
      selector: IAdvancedPoolHooks.preflightCheck.selector,
      sender: address(s_burnMintPool),
      data: payloadData,
      context: tokenArgs
    });

    return abi.encodeWithSelector(
      IPolicyEngine.PolicyRunRejected.selector, address(s_volumePolicy), VOLUME_POLICY_REJECT_REASON, payload
    );
  }

  /// @notice Validates the complete source chain flow: Router -> OnRamp -> BurnMintTokenPool -> AdvancedPoolHooks
  /// -> PolicyEngine -> AdvancedPoolHooksExtractor -> VolumePolicy.
  function test_sourceChain_ccipSend_policyAccepted() public {
    Client.EVM2AnyMessage memory message = _buildAndApproveCcipSend(VALID_AMOUNT);

    uint256 senderBalanceBefore = s_aceToken.balanceOf(OWNER);

    vm.recordLogs();
    s_sourceRouter.ccipSend(DEST_CHAIN_SELECTOR, message);

    uint256 senderBalanceAfter = s_aceToken.balanceOf(OWNER);
    assertEq(
      VALID_AMOUNT, senderBalanceBefore - senderBalanceAfter, "Sender balance should decrease by transfer amount"
    );

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
        assertEq(IAdvancedPoolHooks.preflightCheck.selector, bytes4(logs[i].topics[3]));

        (IPolicyEngine.Parameter[] memory params,) = abi.decode(logs[i].data, (IPolicyEngine.Parameter[], bytes));
        assertEq(7, params.length, "Should have 7 preflight parameters");

        // PARAM_FROM = originalSender
        assertEq(s_extractor.PARAM_FROM(), params[0].name);
        assertEq(OWNER, abi.decode(params[0].value, (address)));

        // PARAM_TO = receiver
        assertEq(s_extractor.PARAM_TO(), params[1].name);
        assertEq(s_receiver, abi.decode(params[1].value, (address)));

        // PARAM_AMOUNT = lockOrBurnIn.amount
        assertEq(s_extractor.PARAM_AMOUNT(), params[2].name);
        assertEq(VALID_AMOUNT, abi.decode(params[2].value, (uint256)));

        // PARAM_AMOUNT_POST_FEE = amount after pool fee
        assertEq(s_extractor.PARAM_AMOUNT_POST_FEE(), params[3].name);
        assertEq(VALID_AMOUNT, abi.decode(params[3].value, (uint256)));

        // PARAM_REMOTE_CHAIN_SELECTOR
        assertEq(s_extractor.PARAM_REMOTE_CHAIN_SELECTOR(), params[4].name);
        assertEq(DEST_CHAIN_SELECTOR, abi.decode(params[4].value, (uint64)));

        // PARAM_TOKEN = local token address
        assertEq(s_extractor.PARAM_TOKEN(), params[5].name);
        assertEq(address(s_aceToken), abi.decode(params[5].value, (address)));

        // PARAM_BLOCK_CONFIRMATION_REQUESTED
        assertEq(s_extractor.PARAM_BLOCK_CONFIRMATION_REQUESTED(), params[6].name);
        assertEq(uint16(0), abi.decode(params[6].value, (uint16)));

        break;
      }
    }

    assertTrue(foundEvent, "PolicyRunComplete event should be emitted");
  }

  // Reverts

  function test_sourceChain_ccipSend_RevertWhen_AmountExceedsMax() public {
    Client.EVM2AnyMessage memory message = _buildAndApproveCcipSend(TOO_HIGH_AMOUNT);

    vm.expectRevert(_expectedPreflightPolicyRevertData(TOO_HIGH_AMOUNT));
    s_sourceRouter.ccipSend(DEST_CHAIN_SELECTOR, message);
  }

  function test_sourceChain_ccipSend_RevertWhen_AmountBelowMin() public {
    Client.EVM2AnyMessage memory message = _buildAndApproveCcipSend(TOO_LOW_AMOUNT);

    vm.expectRevert(_expectedPreflightPolicyRevertData(TOO_LOW_AMOUNT));
    s_sourceRouter.ccipSend(DEST_CHAIN_SELECTOR, message);
  }
}
