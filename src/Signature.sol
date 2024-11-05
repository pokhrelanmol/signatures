// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
import {console} from "forge-std/Test.sol";
contract Signature {
    uint256 public number;
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function setNumberWithSignature(
        uint256 _number,
        bytes calldata signature
    ) public {
        bytes32 messageHash = keccak256(abi.encodePacked(_number));
        console.logBytes32(messageHash);
        address signer = recoverSigner(messageHash, signature);
        require(signer == owner, "Invalid signature");
        number = _number;
    }

    /**
     * @dev Recovers the signer address from a hashed message and a signature.
     */
    function recoverSigner(
        bytes32 messageHash,
        bytes memory signature
    ) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(signature);
        return ecrecover(messageHash, v, r, s);
    }

    /**
     * @dev Splits the signature into r, s, and v components.
     */
    function splitSignature(
        bytes memory sig
    ) public pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Invalid signature length");

        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
    function setNumber(uint256 newNumber) public {
        number = newNumber;
    }

    function increment() public {
        number++;
    }
}
