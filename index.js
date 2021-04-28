const crypto = require("crypto");
const assert = require('assert');
// const payload = require("./payload");
const payload = { test: 1 };

/** 
 * Hybrid encryption 
 * Alice = mobile app
 * Bob = backend
*/

const alice = {};
const bob = {};

/**
 * ALICE
 * */
// Generate RSA keys
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  // The standard secure default length for RSA keys is 2048 bits
  modulusLength: 2048,
});
// Key exchange
alice.privateKey = privateKey;
alice.publicKey = publicKey;
bob.alicePublicKey = publicKey;

console.log(privateKey.toString())

/**
 * BOB
 * */
const symmetricKey = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);

// Encrypt payload - AES 256 (symmetric)
// This could be the standard file encryption for the document app
const cipher = crypto.createCipheriv("aes-256-cbc", symmetricKey, iv);
const aesEncrypted = Buffer.concat([
  cipher.update(JSON.stringify(payload)),
  cipher.final(),
]);
bob.symmetricKey = symmetricKey.toString("hex");
bob.ecryptedPayload = {
  content: aesEncrypted.toString("hex"),
  iv: iv.toString("hex"),
};

// Encrypt symmetric key - RSA (asymmetric)
const rsaEncrypted = crypto.publicEncrypt(
  {
    key: bob.alicePublicKey,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: "sha256",
  },
  // We convert the data string to a buffer using `Buffer.from`
  Buffer.from(bob.symmetricKey)
);
bob.encryptedSymmetricKey = rsaEncrypted.toString("hex");

// Publish encrypted symmetric key, encrypted payload, iv
alice.encryptedSymmetricKey = bob.encryptedSymmetricKey;
alice.ecryptedPayload = bob.ecryptedPayload;

/**
 * ALICE
 * */
// Decrypt symmetric key - RSA (asymmetric)
const rsaDecrypted = crypto.privateDecrypt(
  {
    key: alice.privateKey,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: "sha256",
  },
  Buffer.from(alice.encryptedSymmetricKey, 'hex')
);
alice.symmetricKey = rsaDecrypted.toString();
assert(alice.symmetricKey === bob.symmetricKey);

// Decrypt payload - AES 256 (symmetric)
const decipher = crypto.createDecipheriv(
  "aes-256-cbc",
  Buffer.from(alice.symmetricKey, 'hex'),
  Buffer.from(alice.ecryptedPayload.iv, "hex")
);
const aesDecrypted = Buffer.concat([
  decipher.update(Buffer.from(alice.ecryptedPayload.content, "hex")),
  decipher.final(),
]);
alice.payload = aesDecrypted.toString();
assert(alice.payload === JSON.stringify(payload));

console.log("bob", bob);
console.log("alice", alice);
