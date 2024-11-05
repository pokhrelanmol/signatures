// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {Signature} from "../src/Signature.sol";

contract SignatureTest is Test {
    Signature public signature;
    uint256 key = uint256(keccak256("owner"));
    address owner = vm.addr(key);

    function setUp() public {
        signature = new Signature(owner);
    }

    function test_setNumberWithSignature() public {
        uint256 number = 10;
        bytes32 messageHash = keccak256(abi.encodePacked(number));

        console.logBytes32(messageHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, messageHash);
        bytes memory _signature = abi.encodePacked(r, s, v);
        //increment
        signature.setNumberWithSignature(number, _signature);
        assertEq(signature.number(), number);
    }
}
