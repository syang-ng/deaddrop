// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface Vm {
    function load(address target, bytes32 slot) external view returns (bytes32);
}

contract PinnedState {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function testPinnedValue() external view {
        require(block.number == 1, "unexpected fork height");
        require(vm.load(0x1000000000000000000000000000000000000001, bytes32(0)) == bytes32(uint256(42)),
            "unexpected fixture value");
    }
}
