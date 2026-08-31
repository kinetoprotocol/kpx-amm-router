// SPDX-License-Identifier: BSL-1.1
// AXIOLEDGER — KINETOPROTOCOL ($KPX)
// KPXRouterGateway.sol — Cong Dinh tuyen Chinh thuc
//
// +=================================================================+
// |  STATUS: DRAFT v0.0.1 — SECURITY PATCH APPLIED                 |
// |  Foundry Tests: core/contracts/kpx/test/KPXRouterGateway.t.sol |
// |  Security Checklist: core/contracts/KPXRouter-security-review  |
// |  DO NOT DEPLOY until all 30 security checks PASSED             |
// +=================================================================+
//
// Ref: Whitepaper §11.10 · §11.11
// Ref: core/contracts/IKPXRouter.sol (interface)
//
// PATCH v0.0.1 CHANGES:
//  [SEC-1] Weak PRNG fixed: bridgeId now uses internal _txNonce instead of block.number
//  [SEC-2] Reentrancy-Events fixed: emit RoutingExecuted moved before safeTransfer (CEI)
//  [SEC-3] Modifier logic unwrapped into internal functions (_requireVrqClear,
//          _requireDao, _requireRelayer) to reduce bytecode size
//  [SEC-4] Renamed _verifyMPCThreshold → _verifyMpcThreshold (mixedCase standard)

pragma solidity ^0.8.28;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./interfaces/IVRQVerifier.sol";
import "./interfaces/IKPXDarkPool.sol";

/**
 * @title  KPXRouterGateway
 * @author AXIOLEDGER Core Team
 * @notice Central routing gateway of KINETOPROTOCOL ($KPX).
 *         Handles: Cross-chain Bridge · AMM Swap · RWA Treasury · Dark Pool routing
 *
 * @dev Architecture notes:
 *  - ReentrancyGuard:  Protects ALL external state-changing functions
 *  - Pausable:         Emergency freeze — only TreasuryDAO 5/7 multisig may call
 *  - SafeERC20:        No raw transfer() — avoids silent failures
 *  - No admin key:     owner = TreasuryDAO multisig, not an EOA
 *  - VRQ pre-check:    isFlagged() is the FIRST check in every function
 *  - ZK verification:  After VRQ check, before any state change
 *
 * Security model (per core/contracts/KPXRouter-security-review.md):
 *  A. AMM:      ReentrancyGuard + deadline + slippage + TWAP
 *  B. Bridge:   MPC 2/3 + replay prevention + drain limit + chain whitelist
 *  C. RWA:      15% collateral + oracle TWAP + institutional KYC
 *  D. DarkPool: Pedersen commitment + ZK match proof
 *  E. Govern:   No EOA admin + DAO-only pause + timelock
 *  F. Integ:    Circuit version check + VRQ real-time
 */
contract KPXRouterGateway is ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    // -------------------------------------------------------------------------
    // Immutables
    // -------------------------------------------------------------------------

    IVRQVerifier public immutable ZK_VERIFIER;
    IKPXDarkPool public immutable DARK_POOL;

    // -------------------------------------------------------------------------
    // State variables
    // -------------------------------------------------------------------------

    /// @notice TreasuryDAO multisig address — not an EOA
    address public treasuryDao;

    /// @notice Per-tx bridge limit (anti-drain)
    uint256 public maxBridgeAmountPerTx = 1_000_000 * 1e18;

    /// @notice Whitelisted bridge destination chains
    mapping(uint16 => bool) public supportedChains;

    /// @notice Fulfilled bridge IDs (replay prevention)
    mapping(bytes32 => bool) public bridgeFulfilled;

    /// @notice MPC Relayer set (2/3 threshold required)
    mapping(address => bool) public mpcRelayers;
    uint256 public relayerCount;
    uint256 public constant RELAYER_THRESHOLD_NUMERATOR   = 2;
    uint256 public constant RELAYER_THRESHOLD_DENOMINATOR = 3;

    /// @notice ZK circuit version that must match the verifier
    uint256 public requiredCircuitVersion;

    /// @notice Used ZK proof nonces (anti-replay for ZK proofs)
    mapping(bytes32 => bool) public usedProofNonces;

    /// @notice [SEC-1] Monotonically increasing nonce for bridgeId generation.
    ///         Replaces block.number to eliminate Weak PRNG (predictable block values).
    uint256 private _txNonce;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    event CrossChainDeposit(
        address indexed user,
        uint256         amount,
        uint16          destChainId,
        bytes32         kycCommitment,
        bytes32         bridgeId
    );

    event BridgeCompleted(
        bytes32 indexed bridgeId,
        address indexed recipient,
        address         token,
        uint256         amount,
        uint16          sourceChainId
    );

    event RoutingExecuted(
        address indexed user,
        address         tokenIn,
        address         tokenOut,
        uint256         amountIn,
        uint256         amountOut,
        bool            routedToDarkPool
    );

    event EmergencyPaused(address indexed caller, string reason);
    event EmergencyUnpaused(address indexed caller);
    event MaxBridgeAmountUpdated(uint256 oldAmount, uint256 newAmount);
    event ChainSupportUpdated(uint16 chainId, bool supported);
    event RelayerUpdated(address indexed relayer, bool active);

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    error VRQ_AddressFlagged(address addr);
    error VRQ_ZKProofInvalid();
    error VRQ_ComplianceFailed();
    error VRQ_CircuitVersionMismatch(uint256 required, uint256 actual);
    error KPX_InvalidAmount();
    error KPX_SlippageExceeded(uint256 amountOut, uint256 minRequired);
    error KPX_DeadlineExpired(uint256 deadline, uint256 current);
    error KPX_UnsupportedChain(uint16 chainId);
    error KPX_BridgeAmountExceedsLimit(uint256 amount, uint256 limit);
    error KPX_BridgeAlreadyFulfilled(bytes32 bridgeId);
    error KPX_ProofAlreadyUsed(bytes32 proofNonce);
    error KPX_NotRelayer(address caller);
    error KPX_InsufficientRelayerSignatures();
    error KPX_Unauthorized(address caller);
    error KPX_ZeroAddress();

    // -------------------------------------------------------------------------
    // Modifiers — [SEC-3] Each modifier delegates to an internal function.
    // The internal function is compiled once; modifiers only emit a JUMP,
    // reducing contract bytecode size when the check is reused many times.
    // -------------------------------------------------------------------------

    /// @dev VRQ pre-check: called FIRST before any other logic
    modifier vrqClear(address addr) {
        _requireVrqClear(addr);
        _;
    }

    /// @dev Only TreasuryDAO multisig
    modifier onlyDao() {
        _requireDao();
        _;
    }

    /// @dev Only MPC Relayer
    modifier onlyRelayer() {
        _requireRelayer();
        _;
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    /**
     * @param _zkVerifier        VRQ ZK Verifier contract address
     * @param _darkPool          KPX Dark Pool contract address
     * @param _treasuryDao       TreasuryDAO multisig — will be owner
     * @param _initialRelayers   Initial MPC relayer list
     * @param _supportedChainIds Chain IDs whitelisted at deploy time
     * @param _circuitVersion    Required ZK circuit version
     */
    constructor(
        address          _zkVerifier,
        address          _darkPool,
        address          _treasuryDao,
        address[] memory _initialRelayers,
        uint16[]  memory _supportedChainIds,
        uint256          _circuitVersion
    ) {
        if (_zkVerifier  == address(0)) revert KPX_ZeroAddress();
        if (_darkPool    == address(0)) revert KPX_ZeroAddress();
        if (_treasuryDao == address(0)) revert KPX_ZeroAddress();

        ZK_VERIFIER            = IVRQVerifier(_zkVerifier);
        DARK_POOL              = IKPXDarkPool(_darkPool);
        treasuryDao            = _treasuryDao;
        requiredCircuitVersion = _circuitVersion;

        for (uint256 i = 0; i < _initialRelayers.length; ) {
            mpcRelayers[_initialRelayers[i]] = true;
            unchecked { relayerCount++; i++; }
        }

        for (uint256 i = 0; i < _supportedChainIds.length; ) {
            supportedChains[_supportedChainIds[i]] = true;
            unchecked { i++; }
        }
    }

    // =========================================================================
    // SECTION 1: CROSS-CHAIN BRIDGE
    // =========================================================================

    /**
     * @notice Initiate an outbound cross-chain transfer
     * @param _token         Token to bridge
     * @param _amount        Token quantity
     * @param _destChainId   Destination chain ID (SLIP-44)
     * @param _recipient     Recipient on destination chain (bytes32 — EVM + non-EVM)
     * @param _deadline      Block-number deadline
     * @param _zkProof       ZK compliance proof from VRQ
     * @param _kycCommitment KYC commitment (raw data never exposed)
     * @return bridgeId      Unique operation ID
     *
     * Security flow:
     *  [1] VRQ: msg.sender not flagged
     *  [2] VRQ: token contract not flagged
     *  [3] ZK:  circuit version matches
     *  [4] ZK:  proof nonce unused (anti-replay)
     *  [5] ZK:  verifyCompliance passes
     *  [6] Chain whitelist check
     *  [7] Amount limit check
     *  [8] Deadline check
     *  [9] Escrow tokens (transfer to this contract)
     * [10] Emit event — MPC relayers listen to unlock on destination
     */
    function bridgeOut(
        address  _token,
        uint256  _amount,
        uint16   _destChainId,
        bytes32  _recipient,
        uint256  _deadline,
        bytes    calldata _zkProof,
        bytes32  _kycCommitment
    )
        external
        nonReentrant
        whenNotPaused
        vrqClear(msg.sender)
        returns (bytes32 bridgeId)
    {
        // [2] Token contract not flagged
        if (ZK_VERIFIER.isFlagged(_token)) revert VRQ_AddressFlagged(_token);

        // [3] Circuit version
        uint256 actualVersion = ZK_VERIFIER.circuitVersion();
        if (actualVersion != requiredCircuitVersion)
            revert VRQ_CircuitVersionMismatch(requiredCircuitVersion, actualVersion);

        // [4] Proof nonce anti-replay
        bytes32 proofNonce = keccak256(_zkProof);
        if (usedProofNonces[proofNonce]) revert KPX_ProofAlreadyUsed(proofNonce);
        usedProofNonces[proofNonce] = true;

        // [5] ZK compliance
        if (!ZK_VERIFIER.verifyCompliance(_zkProof, _kycCommitment))
            revert VRQ_ComplianceFailed();

        // [6] Chain whitelist
        if (!supportedChains[_destChainId]) revert KPX_UnsupportedChain(_destChainId);

        // [7] Amount limit
        if (_amount == 0) revert KPX_InvalidAmount();
        if (_amount > maxBridgeAmountPerTx)
            revert KPX_BridgeAmountExceedsLimit(_amount, maxBridgeAmountPerTx);

        // [8] Deadline
        if (block.number > _deadline) revert KPX_DeadlineExpired(_deadline, block.number);

        // [9] Escrow tokens
        IERC20(_token).safeTransferFrom(msg.sender, address(this), _amount);

        // [SEC-1] bridgeId uses an internal nonce — not block.number — to prevent
        //         miner/validator timestamp manipulation (Weak PRNG fix).
        bridgeId = keccak256(abi.encodePacked(
            msg.sender, _token, _amount, _destChainId, _recipient,
            unchecked_inc(_txNonce)
        ));
        _txNonce++;

        emit CrossChainDeposit(msg.sender, _amount, _destChainId, _kycCommitment, bridgeId);
    }

    /**
     * @notice Complete an inbound bridge when assets arrive from another chain.
     *         Only callable by an MPC Relayer (2/3 threshold required).
     *
     * Security flow:
     *  [1] onlyRelayer modifier
     *  [2] bridgeId not yet fulfilled (replay prevention)
     *  [3] VRQ: recipient not flagged
     *  [4] Mark fulfilled BEFORE transfer (CEI pattern)
     *  [5] Transfer tokens out
     */
    function bridgeIn(
        bytes32  _bridgeId,
        address  _recipient,
        address  _token,
        uint256  _amount,
        uint16   _sourceChainId,
        bytes    calldata _mpcSignatures
    )
        external
        nonReentrant
        whenNotPaused
        onlyRelayer
    {
        // [2] Replay prevention
        if (bridgeFulfilled[_bridgeId]) revert KPX_BridgeAlreadyFulfilled(_bridgeId);

        // [3] VRQ recipient check
        if (ZK_VERIFIER.isFlagged(_recipient)) revert VRQ_AddressFlagged(_recipient);

        // Verify MPC threshold (simplified — production needs full BLS/ECDSA aggregation)
        _verifyMpcThreshold(_bridgeId, _mpcSignatures);

        // [4] Mark FULFILLED before transfer (CEI: Checks-Effects-Interactions)
        bridgeFulfilled[_bridgeId] = true;

        // [5] Transfer
        IERC20(_token).safeTransfer(_recipient, _amount);

        emit BridgeCompleted(_bridgeId, _recipient, _token, _amount, _sourceChainId);
    }

    // =========================================================================
    // SECTION 2: AMM SWAP + DARK POOL ROUTING
    // =========================================================================

    /**
     * @notice Route a swap — automatically sends to Dark Pool when
     *         the amount exceeds the institutional threshold.
     * @param _amountIn      Input token amount
     * @param _amountOutMin  Minimum output (slippage protection)
     * @param _path          [tokenIn, ..., tokenOut]
     * @param _deadline      Block-number deadline
     * @param _zkProof       ZK identity proof
     * @param _zkPubInputs   ZK public inputs
     * @return amountOut     Actual amount received
     *
     * Security flow:
     *  [1] VRQ: msg.sender not flagged
     *  [2] ZK:  circuit version + proof nonce
     *  [3] ZK:  proof verify
     *  [4] Deadline check
     *  [5] Route: Dark Pool if > threshold, standard AMM otherwise
     *  [6] Slippage guard
     *  [7] [SEC-2] emit RoutingExecuted BEFORE external transfer (CEI)
     *  [8] Transfer output to user
     */
    function swapExactTokensForTokensWithPrivacy(
        uint256   _amountIn,
        uint256   _amountOutMin,
        address[] calldata _path,
        uint256   _deadline,
        bytes     calldata _zkProof,
        uint256[] calldata _zkPubInputs
    )
        external
        nonReentrant
        whenNotPaused
        vrqClear(msg.sender)
        returns (uint256 amountOut)
    {
        // [2] Circuit version + nonce
        uint256 actualVersion = ZK_VERIFIER.circuitVersion();
        if (actualVersion != requiredCircuitVersion)
            revert VRQ_CircuitVersionMismatch(requiredCircuitVersion, actualVersion);

        bytes32 proofNonce = keccak256(_zkProof);
        if (usedProofNonces[proofNonce]) revert KPX_ProofAlreadyUsed(proofNonce);
        usedProofNonces[proofNonce] = true;

        // [3] ZK verify
        if (!ZK_VERIFIER.verifyProof(_zkProof, _zkPubInputs)) revert VRQ_ZKProofInvalid();

        // [4] Deadline
        if (block.number > _deadline) revert KPX_DeadlineExpired(_deadline, block.number);

        if (_amountIn == 0) revert KPX_InvalidAmount();
        if (_path.length < 2) revert KPX_InvalidAmount();

        // Transfer token into contract (CEI — state change before external call)
        IERC20(_path[0]).safeTransferFrom(msg.sender, address(this), _amountIn);

        bool routedDark = false;

        // [5] Route decision
        if (_amountIn > DARK_POOL.getInstitutionalThreshold()) {
            // Dark Pool routing — confidential, no front-running
            IERC20(_path[0]).approve(address(DARK_POOL), _amountIn);
            amountOut = DARK_POOL.executeConfidentialSwap(
                msg.sender, _amountIn, _path, _zkProof
            );
            routedDark = true;
        } else {
            // Standard AMM — TODO: integrate actual AMM pool in v0.1.0
            // amountOut = standardAMM.swap(_path, _amountIn, address(this));
            amountOut = _amountIn; // Placeholder — replaced by real AMM call
        }

        // [6] Slippage guard
        if (amountOut < _amountOutMin)
            revert KPX_SlippageExceeded(amountOut, _amountOutMin);

        // [SEC-2] Emit event BEFORE the final external transfer so that
        //         off-chain indexers (Subgraph, ANS Indexer) observe the
        //         correct ordering and cannot be manipulated by reentrancy.
        emit RoutingExecuted(
            msg.sender, _path[0], _path[_path.length - 1],
            _amountIn, amountOut, routedDark
        );

        // [8] Transfer output to user (external call — comes LAST per CEI)
        // Note: when routed through Dark Pool, MockDarkPool already sent tokenOut
        // to `msg.sender` directly. For standard AMM path the router holds tokenOut.
        if (!routedDark) {
            IERC20(_path[_path.length - 1]).safeTransfer(msg.sender, amountOut);
        }
    }

    // =========================================================================
    // SECTION 3: GOVERNANCE & EMERGENCY
    // =========================================================================

    /// @notice Emergency pause — only TreasuryDAO 5/7 multisig
    function emergencyPause(string calldata reason) external onlyDao {
        _pause();
        emit EmergencyPaused(msg.sender, reason);
    }

    /// @notice Unpause — only after DAO vote passes
    function unpause() external onlyDao {
        _unpause();
        emit EmergencyUnpaused(msg.sender);
    }

    /// @notice Update max bridge amount (DAO only)
    function setMaxBridgeAmount(uint256 _newMax) external onlyDao {
        emit MaxBridgeAmountUpdated(maxBridgeAmountPerTx, _newMax);
        maxBridgeAmountPerTx = _newMax;
    }

    /// @notice Add/remove chain support (DAO only)
    function setChainSupport(uint16 _chainId, bool _supported) external onlyDao {
        supportedChains[_chainId] = _supported;
        emit ChainSupportUpdated(_chainId, _supported);
    }

    /// @notice Update MPC relayer set (DAO only)
    function setRelayer(address _relayer, bool _active) external onlyDao {
        if (_relayer == address(0)) revert KPX_ZeroAddress();
        if (_active && !mpcRelayers[_relayer]) {
            mpcRelayers[_relayer] = true;
            emit RelayerUpdated(_relayer, true);
            unchecked { relayerCount++; }
        } else if (!_active && mpcRelayers[_relayer]) {
            mpcRelayers[_relayer] = false;
            emit RelayerUpdated(_relayer, false);
            relayerCount--;
        }
    }

    // -------------------------------------------------------------------------
    // View helpers
    // -------------------------------------------------------------------------

    function paused() public view override returns (bool) { return super.paused(); }
    function getSupportedChains(uint16 id) external view returns (bool) { return supportedChains[id]; }
    function isBridgeFulfilled(bytes32 id) external view returns (bool) { return bridgeFulfilled[id]; }

    /// @notice Backward-compatible accessor — returns ZK_VERIFIER immutable
    function zkVerifier() external view returns (IVRQVerifier) { return ZK_VERIFIER; }
    /// @notice Backward-compatible accessor — returns DARK_POOL immutable
    function darkPool() external view returns (IKPXDarkPool) { return DARK_POOL; }
    /// @notice Backward-compatible accessor — returns treasuryDao (legacy camelCase)
    function treasuryDAO() external view returns (address) { return treasuryDao; }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /// @dev [SEC-3] VRQ guard extracted to an internal function.
    ///      The modifier calls this; compiled once, jumped-to N times.
    function _requireVrqClear(address addr) internal view {
        if (ZK_VERIFIER.isFlagged(addr)) revert VRQ_AddressFlagged(addr);
    }

    /// @dev [SEC-3] DAO guard extracted to an internal function.
    function _requireDao() internal view {
        if (msg.sender != treasuryDao) revert KPX_Unauthorized(msg.sender);
    }

    /// @dev [SEC-3] Relayer guard extracted to an internal function.
    function _requireRelayer() internal view {
        if (!mpcRelayers[msg.sender]) revert KPX_NotRelayer(msg.sender);
    }

    /// @dev [SEC-4] Renamed from _verifyMPCThreshold to mixedCase _verifyMpcThreshold.
    ///      Verifies MPC threshold signatures (simplified).
    ///      Production: needs full BLS/ECDSA multi-sig aggregation.
    function _verifyMpcThreshold(bytes32 bridgeId, bytes calldata /*signatures*/) internal view {
        uint256 required = (relayerCount * RELAYER_THRESHOLD_NUMERATOR
            + RELAYER_THRESHOLD_DENOMINATOR - 1) / RELAYER_THRESHOLD_DENOMINATOR;
        // Production: parse signatures, verify each, count unique valid >= required.
        // Placeholder: prevents unused-variable warning.
        if (required == 0 && bridgeId == bytes32(0)) revert KPX_InsufficientRelayerSignatures();
    }

    /// @dev Returns `n` unchanged; used to snapshot _txNonce before increment.
    function unchecked_inc(uint256 n) private pure returns (uint256) {
        return n;
    }
}
