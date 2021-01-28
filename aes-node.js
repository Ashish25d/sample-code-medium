const crypto = require('crypto');
function encrypt(plainString, AesKey, AesIV) {
    const cipher = crypto.createCipheriv("aes-256-cbc", AesKey, AesIV);
    let encrypted = Buffer.concat([cipher.update(Buffer.from(plainString, "utf8")), cipher.final()]);
    return encrypted.toString("base64");
}

function decrypt(base64String, AesKey, AesIV) {
    const decipher = crypto.createDecipheriv("aes-256-cbc", AesKey, AesIV);
    const deciphered = Buffer.concat([decipher.update(Buffer.from(base64String, "base64")), decipher.final()]);
    return deciphered.toString("utf8");
}

const key = crypto.randomBytes(32); //Need 32 bytes (256 bits) key as we are using AES-256 encryption
const iv = crypto.randomBytes(16); //Need 16 bytes (128 bits) Initialization vector as default block size is 128 bits

// Its better to pass iv and key in bytes/buffer
var encryptedData = encrypt("some data to encrypt", key, iv);
console.log(encryptedData);
// Need same key and iv for decryption otherwise it won't work
var decryptedData = decrypt(encryptedData, key, iv)
console.log(decryptedData);
