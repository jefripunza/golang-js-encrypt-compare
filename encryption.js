const crypto = require("crypto");

class Encryption {
  constructor() {
    this.algorithm = "des-ede3-cbc"; // TripleDES algorithm
    this.ivLength = 8; // IV length for TripleDES
  }

  encodeWithSecret(text) {
    const secretKey = this.getSecretKey();
    return this.encode(secretKey, text);
  }

  decodeWithSecret(encodedText) {
    const secretKey = this.getSecretKey();
    return this.decode(secretKey, encodedText);
  }

  encode(secretKey, text) {
    const key = this.hashKey(secretKey);
    const iv = crypto.randomBytes(this.ivLength);

    // Layer 1: TripleDES Encryption with original hashed key
    let encrypted = this.encryptTripleDES(key, iv, text);

    // Layer 2: TripleDES Encryption with reversed hashed key
    const reversedKey = this.hashKey(this.reverseString(key.toString("base64")));
    encrypted = this.encryptTripleDES(reversedKey, iv, encrypted);

    // Layer 3: TripleDES Encryption with first half of the original hashed key rehashed
    const firstHalfKey = this.hashKey(key.toString("base64").slice(0, key.length / 2));
    encrypted = this.encryptTripleDES(firstHalfKey, iv, encrypted);

    // Layer 4: TripleDES Encryption with second half of the original hashed key rehashed
    const secondHalfKey = this.hashKey(key.toString("base64").slice(key.length / 2));
    encrypted = this.encryptTripleDES(secondHalfKey, iv, encrypted);

    // Combine IV and encrypted data, then Base64 encode
    const combinedData = Buffer.concat([iv, encrypted]);
    return combinedData.toString("base64");
  }

  decode(secretKey, encodedText) {
    const key = this.hashKey(secretKey);
    const combinedData = Buffer.from(encodedText, "base64");

    // Extract IV from the combined data
    const iv = combinedData.slice(0, this.ivLength);
    const encrypted = combinedData.slice(this.ivLength);

    // Layer 4: TripleDES Decryption with second half of the original hashed key rehashed
    const secondHalfKey = this.hashKey(key.toString("base64").slice(key.length / 2));
    let decrypted = this.decryptTripleDES(secondHalfKey, iv, encrypted);

    // Layer 3: TripleDES Decryption with first half of the original hashed key rehashed
    const firstHalfKey = this.hashKey(key.toString("base64").slice(0, key.length / 2));
    decrypted = this.decryptTripleDES(firstHalfKey, iv, decrypted);

    // Layer 2: TripleDES Decryption with reversed hashed key
    const reversedKey = this.hashKey(this.reverseString(key.toString("base64")));
    decrypted = this.decryptTripleDES(reversedKey, iv, decrypted);

    // Layer 1: TripleDES Decryption with original hashed key
    decrypted = this.decryptTripleDES(key, iv, decrypted);

    return decrypted.toString("utf8").trim();
  }

  getSecretKey() {
    const secretKey = process.env.SECRET_KEY || "your_secret_key";
    return secretKey;
  }

  reverseString(str) {
    return str.split("").reverse().join("");
  }

  hashKey(key) {
    const hasher = crypto.createHash("sha256");
    hasher.update(key);
    // Return the first 24 bytes for TripleDES key
    return hasher.digest().slice(0, 24);
  }

  encryptTripleDES(key, iv, text) {
    const cipher = crypto.createCipheriv(this.algorithm, key, iv);
    let encrypted = cipher.update(text, "utf8");
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return encrypted;
  }

  decryptTripleDES(key, iv, encrypted) {
    const decipher = crypto.createDecipheriv(this.algorithm, key, iv);
    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted;
  }
}

module.exports = Encryption;
