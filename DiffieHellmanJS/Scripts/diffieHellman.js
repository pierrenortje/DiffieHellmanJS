function DiffieHellman() {

    var generatePrivateKey = function() {
        var random = new Uint8Array(32);
        gostCrypto.getRandomValues(random);
        return GostCoding.prototype.Hex.encode(random);
    };

    var generatePublicKey = function(privateKey) {
        // Generate public key
        var algorithm = {
            name: 'GOST R 34.10'
        };

        // Preset if private key already defined
        algorithm.ukm = GostCoding.prototype.Hex.decode(privateKey);

        // Set curve parameters
        algorithm.namedCurve = 'S-256-A'; // id-GostR3410-2001-CryptoPro-A-ParamSet

        // Generate keys
        return gostCrypto.subtle.generateKey(algorithm, true, ['sign', 'verify']).then(function(keyPair) {

            // Store key in secure location
            return gostCrypto.subtle.exportKey('raw', keyPair.privateKey).then(function(result) {

                // Provide the public key to recipient
                return gostCrypto.subtle.exportKey('raw', keyPair.publicKey).then(function(result) {
                    return GostCoding.prototype.Hex.encode(result);
                });
            });
        });
    };

    this.privateKey = generatePrivateKey();
    this.publicKey = generatePublicKey(this.privateKey);

    this.encrypt = function(publicKey, secretMessage) {
		
        var result = {};
		
        return gostCrypto.subtle.importKey(
            'raw',
            gostCrypto.coding.Hex.decode(this.privateKey), {
                name: 'GOSTR3410'
            },
            true, ['deriveKey', 'sign']
        ).then(function(baseKey) {

            // Get peer's public key
            return gostCrypto.subtle.importKey(
                'raw',
                gostCrypto.coding.Hex.decode(publicKey), {
                    name: 'GOSTR3410'
                },
                true, ['deriveKey', 'verify']
            ).then(function(pubKey) {

                var userKeyMaterial = new Uint8Array(8);
                gostCrypto.getRandomValues(userKeyMaterial);
                result.ukmKey = gostCrypto.coding.Hex.encode(userKeyMaterial);

                // Use peer's public, own private key and seed for create derive key
                return gostCrypto.subtle.deriveKey({
                        name: 'GOSTR3410',
                        hash: {
                            name: 'GOSTR3411'
                        },
                        ukm: userKeyMaterial,
                        public: pubKey
                    },
                    baseKey, {
                        name: 'GOST28147'
                    },
                    false, ['wrapKey']
                ).then(function(keyEncryptionKey) {

                    // Generate contentEncryptionKey (Conten Encryption Key)
                    return gostCrypto.subtle.generateKey({
                            name: 'GOST28147'
                        },
                        false, ['encrypt']
                    ).then(function(contentEncryptionKey) {

                        // Encrypt message by using contentEncryptionKey. Encrypted message will send 
                        // with wrapped contentEncryptionKey
                        return gostCrypto.subtle.encrypt({
                                name: 'GOST28147-CFB'
                            },
                            contentEncryptionKey,
                            gostCrypto.coding.Chars.decode(secretMessage, 'win1251')
                        ).then(function(data) {
                            result.encrypted = gostCrypto.coding.Base64.encode(data);

                            // Wrap contentEncryptionKey by using keyEncryptionKey and pseudo random UKM 
                            return gostCrypto.subtle.wrapKey(
                                'raw',
                                contentEncryptionKey,
                                keyEncryptionKey, {
                                    name: 'GOST28147',
                                    ukm: userKeyMaterial
                                }
                            );
                        }).then(function(encryptedKey) {
                            result.wrappedKey = gostCrypto.coding.Hex.encode(encryptedKey);
                            return result;
                        });
                    });
                });
            });
        }).catch(function(error) {
            alert(error.message);
        });
    };

    this.decrypt = function(publicKey, encryptedMessage, wrappedKey, ukmKey) {

        // Get private key from secluded place
        return gostCrypto.subtle.importKey('raw', gostCrypto.coding.Hex.decode(this.privateKey), {
            name: 'GOSTR3410'
        }, true, ['deriveKey', 'sign']).then(function(baseKey) {

            // Get peer's public key
            return gostCrypto.subtle.importKey('raw', gostCrypto.coding.Hex.decode(publicKey), {
                name: 'GOSTR3410'
            }, true, ['deriveKey', 'verify']).then(function(pubKey) {

                // Get userKeyMaterial 
                var encryptedKey = gostCrypto.coding.Hex.decode(wrappedKey);
                var userKeyMaterial = gostCrypto.coding.Hex.decode(ukmKey);

                // Use peer's public, own private key and seed for create derive key
                return gostCrypto.subtle.deriveKey({
                    name: 'GOSTR3410',
                    hash: {
                        name: 'GOSTR3411'
                    },
                    ukm: userKeyMaterial,
                    public: pubKey
                }, baseKey, {
                    name: 'GOST28147'
                }, true, ['unwrapKey']).then(function(keyEncryptionKey) {

                    // Unwrap contentEncryptionKey using keyEncryptionKey
                    return gostCrypto.subtle.unwrapKey('raw', encryptedKey, keyEncryptionKey, {
                        name: 'GOST28147',
                        ukm: userKeyMaterial
                    }, {
                        name: 'GOST28147'
                    }, false, ['decrypt']);
                }).then(function(contentEncryptionKey) {

                    // Decrypt message
                    return gostCrypto.subtle.decrypt({
                            name: 'GOST28147-CFB'
                        }, contentEncryptionKey,
                        gostCrypto.coding.Base64.decode(encryptedMessage));
                }).then(function(data) {
                    return gostCrypto.coding.Chars.encode(data, 'win1251');
                });
            });
        }).catch(function(error) {
            alert(error.message);
        });
    };

    this.log = function() {
        console.log('Private Key: ' + this.privateKey);
        console.log('Public Key: ' + this.publicKey);
    };

    return {
        publicKey: this.publicKey,
        privateKey: this.privateKey,

        encrypt: this.encrypt,
        decrypt: this.decrypt,

        log: this.log
    }
};