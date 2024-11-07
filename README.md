## Signatures using EIP-712 

In this brach we are using our final standard, that is EIP-712 to format the 
signature and verify it, this signature user a specific format so it cannot be replayed. 

`0x19 0x01 <domainSeparator> <hashStruct(message)>`

This is how the format will look like 

0x19: this is indicating that this is ethereum sig same as in 191. 
0x01: version of 191, you can see this in EIP-191 page
domainSeperator: data specific to this version of 191. it contains a lot of things to protect against the replay attack. 

The domain seperator is a hash of the specific struct format according to EIP and it is know as EIP712Domain

```js
struct EIP712Domain {	
	string name;
	string version;
	uint256 chainId;
	address verifyingContract;
	// bytes32 salt; not required
}
```

hashStruct<message>: This is simply a hash of a message struct containing the message to sign, it can be anything. 

The hashStruct here might be little confusing but it is simply a hash of the struct type you want to sign(also called typehash), for example for EIP712Domain the hash struct will be

```js
bytes32 constant EIP712DOMAIN_TYPEHASH =
	keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
	
``` 

Now we have the typeHash, next step is to fill the data according to this struct for example

```js
// Define what the "domain" struct looks like.
EIP712Domain eip_712_domain_separator_struct = EIP712Domain({
	name: "SignatureVerifier", // this can be anything
	version: "1", // this can be anything
	chainId: 1, // ideally the chainId
	verifyingContract: address(this) // ideally, set this as "this", but can be any contract to verify signatures
});
```
 Using the typeHash and actual data in it, we can create a domainSeperator like this

 ```js
// Now the format of the signatures is known, define who is going to verify the signatures.
bytes32 public immutable i_domain_separator = keccak256(
	abi.encode(
		EIP712DOMAIN_TYPEHASH,
		keccak256(bytes(eip_712_domain_separator_struct.name)),
		keccak256(bytes(eip_712_domain_separator_struct.version)),
		eip_712_domain_separator_struct.chainId,
		eip_712_domain_separator_struct.verifyingContract
	)
);
 ```

We still haven't created a stuct for our message so we will create it and also get the typeHash from that

```js
// define what the message hash struct looks like.
struct Message {
	uint256 number;
}

bytes32 public constant MESSAGE_TYPEHASH = keccak256("Message(uint256 number)");
```

After this the we need to hash the actual message with along with this typeHash

```js
bytes32 hashedMessage = keccak256(abi.encode(MESSAGE_TYPEHASH, Message({ number: message })));

```

this is  what actually fomatting is doing 

0x19 0x01 <hash of who verifies this signature, and what the verifier looks like> < hash of signed structured message, and what the signature looks like>

Now we have all the data to sign to sign a message, next thing will be to verify the signature 

```js
function getSignerEIP712(uint256 message, uint8 _v, bytes32 _r, bytes32 _s) public view returns (address) {
	// Arguments when calculating hash to validate
	// 1: byte(0x19) - the initial 0x19 byte
	// 2: byte(1) - the version byte
	// 3: hashstruct of domain separator (includes the typehash of the domain struct)
	// 4: hashstruct of message (includes the typehash of the message struct)

	bytes1 prefix = bytes1(0x19);
	bytes1 eip712Version = bytes1(0x01); // EIP-712 is version 1 of EIP-191
	bytes32 hashStructOfDomainSeparator = i_domain_separator;

	// hash the message struct
	bytes32 hashedMessage = keccak256(abi.encode(MESSAGE_TYPEHASH, Message({ number: message })));

	// And finally, combine them all
	bytes32 digest = keccak256(abi.encodePacked(prefix, eip712Version, hashStructOfDomainSeparator, hashedMessage));
	return ecrecover(digest, _v, _r, _s);
}
```

Now we can use the singer to verify against the authentic one. 


We will add the replay protection on next version. 

