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
    function test_setNumberWithSignatureEIP191() public {
        uint256 number = 10;

        bytes1 prefix = bytes1(0x19);
        bytes1 eip191Version = bytes1(0);
        address indendedValidatorAddress = address(signature);
        bytes32 applicationSpecificData = keccak256(abi.encodePacked(number));
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                prefix,
                eip191Version,
                indendedValidatorAddress,
                applicationSpecificData
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, messageHash);
        bytes memory _signature = abi.encodePacked(r, s, v);
        //increment
        signature.setNumberWithSignatureEIP191(number, _signature);
        assertEq(signature.number(), number);
    }

    //The implentation is not protected against replay attack

    function testSignatureReplayAttack() public {
        uint256 number = 10;

        bytes1 prefix = bytes1(0x19);
        bytes1 eip191Version = bytes1(0);
        address indendedValidatorAddress = address(signature);
        bytes32 applicationSpecificData = keccak256(abi.encodePacked(number));
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                prefix,
                eip191Version,
                indendedValidatorAddress,
                applicationSpecificData
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, messageHash);
        bytes memory _signature = abi.encodePacked(r, s, v);
        //increment
        signature.setNumberWithSignatureEIP191(number, _signature);
        assertEq(signature.number(), number);

        //@note The same signature can be used again to set the number, Imagine this
        // was a token transfer rather then setting the number, this would have drained all the
        // user funds.

        signature.setNumberWithSignatureEIP191(number, _signature);

        assertEq(signature.number(), number);
    }
}
