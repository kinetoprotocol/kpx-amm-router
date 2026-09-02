// SPDX-License-Identifier: BSL-1.1
// AXIOLEDGER  KINETOPROTOCOL ($KPX)
// IKPXDarkPool.sol  Dark Pool Interface
// Ref: Whitepaper 11.11  IKPXRouter.sol Section 4

pragma solidity ^0.8.24;

/// @title IKPXDarkPool
/// @notice Interface cho AXIO Dark Pool  block trades n danh, khng front-running
/// @dev Dng Pedersen commitment + ZK Match Proof
interface IKPXDarkPool {
    /// @notice Ly ngng ti sn  route vo Dark Pool (institutional threshold)
    /// @return threshold S lng token (18 decimals)  kch hot Dark Pool routing
    function getInstitutionalThreshold() external view returns (uint256 threshold);

    /// @notice Thc thi confidential swap qua Dark Pool
    /// @param sender    a ch ngi thc hin swap
    /// @param amountIn  S lng token u vo
    /// @param path      ng i token [tokenIn, ..., tokenOut]
    /// @param zkProof   ZK-Proof n danh t VRQ
    /// @return amountOut S lng token nhn c
    ///
    /// @dev Ch KPXRouterGateway c gi hm ny (role check)
    function executeConfidentialSwap(
        address sender,
        uint256 amountIn,
        address[] calldata path,
        bytes calldata zkProof
    ) external returns (uint256 amountOut);

    /// @notice t lnh n (commitment khng tit l amount/direction)
    /// @param commitment Pedersen commitment: C = r*G + v*H
    /// @param expiry     Block number ht hn
    /// @return orderId   ID duy nht
    function placeSealedOrder(
        bytes32 commitment,
        uint256 expiry
    ) external payable returns (bytes32 orderId);

    /// @notice Kim tra order tn ti v cn hiu lc
    function isOrderActive(bytes32 orderId) external view returns (bool active);
}
