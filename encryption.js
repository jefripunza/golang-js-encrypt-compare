const crypto = require("crypto");

// -------------------------------------------------------------------
// -------------------------------------------------------------------

function getSecretKey() {
  const secretKey = process.env.SECRET_KEY || "your_secret_key";
  return secretKey;
}

function hashKey(key, length) {
  const hasher = crypto.createHash("sha256");
  const hashed = hasher.update(key).digest();
  return hashed.slice(0, length);
}

function reverseString(str) {
  return str.split("").reverse().join("");
}

// -------------------------------------------------------------------
// -------------------------------------------------------------------

function encryptTripleDES(plaintext, key) {
  key = hashKey(key, 24);
  let cipher = crypto.createCipheriv("des-ede3-cbc", key, key.slice(0, 8));
  let encrypted = cipher.update(plaintext, "utf8", "base64");
  encrypted += cipher.final("base64");
  return encrypted;
}

function decryptTripleDES(ciphertext, key) {
  key = hashKey(key, 24);
  let decipher = crypto.createDecipheriv("des-ede3-cbc", key, key.slice(0, 8));
  let decrypted = decipher.update(ciphertext, "base64", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// -------------------------------------------------------------------

function encryptAES(plaintext, secret_key) {
  const key = hashKey(secret_key, 32);
  const iv = hashKey(secret_key, 16);
  let cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  let encrypted = cipher.update(plaintext, "utf8", "base64");
  encrypted += cipher.final("base64");
  return encrypted;
}
function decryptAES(ciphertext, secret_key) {
  const key = hashKey(secret_key, 32);
  const iv = hashKey(secret_key, 16);
  let decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  let decrypted = decipher.update(ciphertext, "base64", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// -------------------------------------------------------------------

function encryptMethod(plainText, key) {
  // console.log("plainText:", plainText, "key:", key);

  return encryptTripleDES(plainText, key);
  // return encryptAES(plainText, key);
}
function decryptMethod(cipherText, key) {
  return decryptTripleDES(cipherText, key);
  // return decryptAES(cipherText, key);
}

// -------------------------------------------------------------------
// -------------------------------------------------------------------

function encode(secretKey, text) {
  // Layer 1: AES Encryption with original hashed key
  let encrypted = encryptMethod(text, secretKey);
  console.log("nodejs encode layer 1:", encrypted);

  // Layer 2: AES Encryption with reversed hashed key
  const reversedKey = reverseString(secretKey);
  encrypted = encryptMethod(encrypted, reversedKey);
  console.log("nodejs encode layer 2:", encrypted);

  // Layer 3: AES Encryption with first half of the original hashed key rehashed
  const firstHalfKey = secretKey.slice(0, secretKey.length / 2);
  encrypted = encryptMethod(encrypted, firstHalfKey);
  console.log("nodejs encode layer 3:", encrypted);

  // Layer 4: AES Encryption with second half of the original hashed key rehashed
  const secondHalfKey = secretKey.slice(secretKey.length / 2);
  encrypted = encryptMethod(encrypted, secondHalfKey);
  console.log("nodejs encode layer 4:", encrypted);

  // Layer 5: Base64 encode
  encrypted = Buffer.from(encrypted).toString("base64");
  console.log("nodejs encode layer 5:", encrypted);

  return encrypted;
}

function decode(secretKey, encodedText) {
  // Layer 5: Base64
  let decrypted = Buffer.from(encodedText, "base64").toString("ascii");
  console.log("nodejs decode layer 5:", decrypted);

  // Layer 4: AES Decryption with second half of the original hashed key rehashed
  const secondHalfKey = secretKey.slice(secretKey.length / 2);
  decrypted = decryptMethod(decrypted, secondHalfKey);
  console.log("nodejs decode layer 4:", decrypted);

  // Layer 3: AES Decryption with first half of the original hashed key rehashed
  const firstHalfKey = secretKey.slice(0, secretKey.length / 2);
  decrypted = decryptMethod(decrypted, firstHalfKey);
  console.log("nodejs decode layer 3:", decrypted);

  // Layer 2: AES Decryption with reversed hashed key
  const reversedKey = reverseString(secretKey);
  decrypted = decryptMethod(decrypted, reversedKey);
  console.log("nodejs decode layer 2:", decrypted);

  // Layer 1: AES Decryption with original hashed key
  decrypted = decryptMethod(decrypted, secretKey);
  console.log("nodejs decode layer 1:", decrypted);

  return decrypted.toString("utf8").trim();
}

// -------------------------------------------------------------------
// -------------------------------------------------------------------

function encodeWithSecret(text) {
  const secretKey = getSecretKey();
  return encode(secretKey, text);
}

function decodeWithSecret(encodedText) {
  const secretKey = getSecretKey();
  return decode(secretKey, encodedText);
}

module.exports = {
  hashKey,
  getSecretKey,
  //
  encodeWithSecret,
  decodeWithSecret,
};
