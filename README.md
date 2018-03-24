# DiffieHellmanJS
A JavaScript implementation of DiffieHellman.

This implementation makes use of the GOST libraries found at: http://gostcrypto.com

I have added a DiffieHellman component to handle the encryption and decryption.

Example:

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
