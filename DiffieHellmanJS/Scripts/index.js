var bob = DiffieHellman();

bob.publicKey.then(function (bobPublicKey) {
    document.getElementById("bobPublicKey").value = bobPublicKey;
});

var alice = DiffieHellman();

alice.publicKey.then(function (alicePublicKey) {
    document.getElementById("alicePublicKey").value = alicePublicKey;
});

var jeff = DiffieHellman();

function encryptText() {

    var alicePublicKey = document.getElementById("alicePublicKey").value;
    var text = document.getElementById("message").value;

    bob.encrypt(alicePublicKey, text).then(function (encryptedData) {

        document.getElementById("encrypted").value = encryptedData.encrypted;

        document.getElementById("wrappedKey").value = encryptedData.wrappedKey;

        document.getElementById("ukmKey").value = encryptedData.ukmKey;
    });
}

function decryptText() {

    var bobPublicKey = document.getElementById("bobPublicKey").value;

    var encrypted = document.getElementById("encrypted").value;
    var wrappedKey = document.getElementById("wrappedKey").value;
    var ukmKey = document.getElementById("ukmKey").value;

    alice.decrypt(bobPublicKey, encrypted, wrappedKey, ukmKey).then(function (decryptedData) {

        //console.log("decryptedData: " + decryptedData);

        alert("Decrypted data: " + decryptedData);

        // This won't work!
        //jeff.decrypt(bobPublicKey, encrypted, wrappedKey, ukmKey).then(function(decryptedData){
        //	console.log("decryptedData: "+decryptedData);
        //});
    });
}