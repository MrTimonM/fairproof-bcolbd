// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// @notice Minimal contract used to prove the permissioned network accepts
///         and finalizes real transactions before any protocol code exists.
contract Ping {
    uint256 public count;
    event Pinged(address indexed from, uint256 count);

    function ping() external {
        count += 1;
        emit Pinged(msg.sender, count);
    }
}
