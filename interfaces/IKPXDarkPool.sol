// SPDX-License-Identifier: BSL-1.1
// AXIOLEDGER — KINETOPROTOCOL ($KPX)
// IKPXDarkPool.sol — Dark Pool Interface
// Ref: Whitepaper §11.11 · IKPXRouter.sol Section 4

pragma solidity ^0.8.24;

/// @title IKPXDarkPool
/// @notice Interface cho AXIO Dark Pool — block trades ẩn danh, không front-running
/// @dev Dùng Pedersen commitment + ZK Match Proof
interface IKPXDarkPool {
    /// @notice Lấy ngưỡng tài sản để route vào Dark Pool (institutional threshold)
    /// @return threshold Số lượng token (18 decimals) để kích hoạt Dark Pool routing
    function getInstitutionalThreshold() external view returns (uint256 threshold);

    /// @notice Thực thi confidential swap qua Dark Pool
    /// @param sender    Địa chỉ người thực hiện swap
    /// @param amountIn  Số lượng token đầu vào
    /// @param path      Đường đi token [tokenIn, ..., tokenOut]
    /// @param zkProof   ZK-Proof ẩn danh từ VRQ
    /// @return amountOut Số lượng token nhận được
    ///
    /// @dev Chỉ KPXRouterGateway được gọi hàm này (role check)
    function executeConfidentialSwap(
        address sender,
        uint256 amountIn,
        address[] calldata path,
        bytes calldata zkProof
    ) external returns (uint256 amountOut);

    /// @notice Đặt lệnh ẩn (commitment không tiết lộ amount/direction)
    /// @param commitment Pedersen commitment: C = r*G + v*H
    /// @param expiry     Block number hết hạn
    /// @return orderId   ID duy nhất
    function placeSealedOrder(
        bytes32 commitment,
        uint256 expiry
    ) external payable returns (bytes32 orderId);

    /// @notice Kiểm tra order tồn tại và còn hiệu lực
    function isOrderActive(bytes32 orderId) external view returns (bool active);
}
