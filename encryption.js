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

    // Layer 1: TripleDES Encryption with original hashed key
    let encrypted = this.encryptMethod(key, text);

    // Layer 2: TripleDES Encryption with reversed hashed key
    const reversedKey = this.hashKey(
      this.reverseString(key.toString("base64"))
    );
    encrypted = this.encryptMethod(reversedKey, encrypted);

    // Layer 3: TripleDES Encryption with first half of the original hashed key rehashed
    const firstHalfKey = this.hashKey(
      key.toString("base64").slice(0, key.length / 2)
    );
    encrypted = this.encryptMethod(firstHalfKey, encrypted);

    // Layer 4: TripleDES Encryption with second half of the original hashed key rehashed
    const secondHalfKey = this.hashKey(
      key.toString("base64").slice(key.length / 2)
    );
    encrypted = this.encryptMethod(secondHalfKey, encrypted);

    // Combine IV and encrypted data, then Base64 encode
    const combinedData = Buffer.concat([encrypted]);
    return combinedData.toString("base64");
  }

  decode(secretKey, encodedText) {
    const key = this.hashKey(secretKey);
    const combinedData = Buffer.from(encodedText, "base64");

    // Extract IV from the combined data
    const encrypted = combinedData.slice(this.ivLength);

    // Layer 4: TripleDES Decryption with second half of the original hashed key rehashed
    const secondHalfKey = this.hashKey(
      key.toString("base64").slice(key.length / 2)
    );
    let decrypted = this.decryptMethod(secondHalfKey, encrypted);

    // Layer 3: TripleDES Decryption with first half of the original hashed key rehashed
    const firstHalfKey = this.hashKey(
      key.toString("base64").slice(0, key.length / 2)
    );
    decrypted = this.decryptMethod(firstHalfKey, decrypted);

    // Layer 2: TripleDES Decryption with reversed hashed key
    const reversedKey = this.hashKey(
      this.reverseString(key.toString("base64"))
    );
    decrypted = this.decryptMethod(reversedKey, decrypted);

    // Layer 1: TripleDES Decryption with original hashed key
    decrypted = this.decryptMethod(key, decrypted);

    return decrypted.toString("utf8").trim();
  }

  getSecretKey() {
    const secretKey = process.env.SECRET_KEY || "your_secret_key";
    return secretKey;
  }

  hashKey(key) {
    const hasher = crypto.createHash("sha256");
    hasher.update(key);
    // Return the first 24 bytes for TripleDES key
    return hasher.digest().slice(0, 24);
  }

  reverseString(str) {
    return str.split("").reverse().join("");
  }

  encryptMethod(key, plaintext) {
    const block = crypto.createCipheriv("des-ede-cbc", key, Buffer.alloc(8)); // 3DES dengan CBC mode, IV di-set ke Buffer kosong

    // Encrypt the plaintext
    let encrypted = block.update(plaintext, "utf8", "base64");
    encrypted += block.final("base64");

    // Combine IV and ciphertext
    const iv = block.getIV(); // Ambil IV yang di-generate secara otomatis
    const combinedData = Buffer.concat([iv, Buffer.from(encrypted, "base64")]);

    return combinedData.toString("base64");
  }

  decryptMethod(key, encodedText) {
    const combinedData = Buffer.from(encodedText, "base64");
    const iv = combinedData.slice(0, 8); // Ambil 8 byte pertama sebagai IV
    const ciphertext = combinedData.slice(8); // Sisa data adalah ciphertext

    const decipher = crypto.createDecipheriv("des-ede-cbc", key, iv);

    // Decrypt the ciphertext
    let decrypted = decipher.update(ciphertext, "base64", "utf8");
    decrypted += decipher.final("utf8");

    return decrypted;
  }
}

module.exports = Encryption;
