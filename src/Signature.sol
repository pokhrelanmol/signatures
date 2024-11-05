// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
import {console} from "forge-std/Test.sol";
contract Signature {
    uint256 public number;
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    // Normal function without EIP's
    function setNumberWithSignature(
        uint256 _number,
        bytes calldata signature
    ) public {
        bytes32 messageHash = keccak256(abi.encodePacked(_number));
        address signer = recoverSigner(messageHash, signature);
        require(signer == owner, "Invalid signature");
        // Increment nonce to prevent replay attacks

        number = _number;
    }

    // Use EIP-191 version 0x00 to format the data
    function setNumberWithSignatureEIP191(
        uint256 _number,
        bytes calldata signature
    ) public {
        bytes32 messageHash = getMessageHash(_number);
        address signer = recoverSigner(messageHash, signature);
        require(signer == owner, "Invalid signature");
        // Increment nonce to prevent replay attacks

        number = _number;
    }

    /**
     * @dev Returns the prefixed hash of the message, adding ERC-191 compliance.
     */
    function getMessageHash(uint256 newNumber) public view returns (bytes32) {
        bytes1 prefix = bytes1(0x19);
        bytes1 eip191Version = bytes1(0);
        address indendedValidatorAddress = address(this);
        bytes32 applicationSpecificData = keccak256(
            abi.encodePacked(newNumber)
        );

        // Apply the ERC-191 prefix
        return
            keccak256(
                abi.encodePacked(
                    prefix,
                    eip191Version,
                    indendedValidatorAddress,
                    applicationSpecificData
                )
            );
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
