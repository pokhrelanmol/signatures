// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
import {console} from "forge-std/Test.sol";

//@note These simple demos are not protected against replay attack.
contract Signature {
    uint256 public number;
    address public owner;
    /* -------------------------- Stuffs related to 712 ------------------------- */
    struct EIP712Domain {
        string name;
        string version;
        uint256 chainId;
        address verifyingContract;
        // bytes32 salt; not required
    }

    // The hash of the EIP721 domain struct
    bytes32 constant EIP712DOMAIN_TYPEHASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

    // Define what the "domain" struct looks like.
    EIP712Domain eip_712_domain_separator_struct =
        EIP712Domain({
            name: "Signature", // this can be anything
            version: "1", // this can be anything
            chainId: 1, // ideally the chainId
            verifyingContract: address(this) // ideally, set this as "this", but can be any contract to verify signatures
        });

    // Now the format of the signatures is known, define who is going to verify the signatures.
    bytes32 public immutable DOMAIN_SEPERATOR =
        keccak256(
            abi.encode(
                EIP712DOMAIN_TYPEHASH,
                keccak256(bytes(eip_712_domain_separator_struct.name)),
                keccak256(bytes(eip_712_domain_separator_struct.version)),
                eip_712_domain_separator_struct.chainId,
                eip_712_domain_separator_struct.verifyingContract
            )
        );

    // define what the message hash struct looks like.
    struct Message {
        uint256 number;
    }

    bytes32 public constant MESSAGE_TYPEHASH =
        keccak256("Message(uint256 number)");

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
        bytes32 messageHash = getMessageHashEIP191(_number);
        address signer = recoverSigner(messageHash, signature);
        require(signer == owner, "Invalid signature");
        // Increment nonce to prevent replay attacks

        number = _number;
    }

    function setNumberWithSignatureEIP712(
        uint256 _number,
        bytes calldata signature
    ) public {
        bytes32 messageHash = getMessageHashEIP712(_number);
        address signer = recoverSigner(messageHash, signature);
        require(signer == owner, "Invalid signature");

        number = _number;
    }

    function getMessageHashEIP712(
        uint256 newNumber
    ) public view returns (bytes32 digest) {
        bytes1 prefix = bytes1(0x19);
        bytes1 eip712Version = bytes1(0x01); // EIP-712 is version 1 of EIP-191
        bytes32 domainSeparatorHash = DOMAIN_SEPERATOR;

        bytes32 hashedMessage = keccak256(
            abi.encode(MESSAGE_TYPEHASH, Message({number: newNumber}))
        );

        //Now with all this in place we finally hash it
        digest = keccak256(
            abi.encodePacked(
                prefix,
                eip712Version,
                domainSeparatorHash,
                hashedMessage
            )
        );
    }
    /**
     * @dev Returns the prefixed hash of the message, adding ERC-191 compliance.
     */
    function getMessageHashEIP191(
        uint256 newNumber
    ) public view returns (bytes32) {
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

    function getDomainSeperatorStruct()
        public
        view
        returns (EIP712Domain memory)
    {
        return eip_712_domain_separator_struct;
    }
}
