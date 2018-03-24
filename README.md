# DiffieHellmanJS
A JavaScript implementation of DiffieHellman.

This implementation makes use of the GOST libraries found at: http://gostcrypto.com

I have added a DiffieHellman component to handle the encryption and decryption.

## Introduction
Snippit from [Wikipedia](https://en.wikipedia.org/wiki/GOST_(block_cipher)):

> "Developed in the 1970s, the standard had been marked "Top Secret" and then downgraded
> to "Secret" in 1990. Shortly after the dissolution of the USSR, it was declassified
> and it was released to the public in 1994..."

## Example

```javascript
var bob = DiffieHellman();

bob.publicKey.then(function (bobPublicKey) {
    // Use bobPublicKey as Bob's public key
});

var alice = DiffieHellman();

alice.publicKey.then(function (alicePublicKey) {
    // Use alicePublicKey as Alice's public key
});

// Bob encrypts data to send to Alice using:
bob.encrypt(alicePublicKey, "Some message to encrypt").then(function (encryptedData) {
  // Send encryptedData to Alice so that she can derypt the message
});

// Alice decrypts the data she received from Bob using:
alice.decrypt(bobPublicKey, encryptedData.encrypted, encryptedData.wrappedKey, encryptedData.ukmKey)
  .then(function (decryptedMessage) {
      alert("Decrypted message from Bob: " + decryptedMessage);
  });
```
