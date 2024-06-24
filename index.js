const fs = require("fs");
const { encodeWithSecret, decodeWithSecret } = require("./encryption");

let message = "berhasil...";
console.log("NodeJS Message:", message);

// ============================================================
// ============================================================

let ciphertext = encodeWithSecret(message);
console.log("NodeJS Encode:", ciphertext);
let decoded = decodeWithSecret(ciphertext);
console.log("NodeJS Decode:", decoded);

// Baca isi file encrypted.txt
fs.readFile("encrypted.txt", "utf8", (err, data) => {
  if (err) {
    console.error("Gagal membaca file:", err);
    return;
  }

  // Dekripsi isi file
  const decrypted = decodeWithSecret(data.trim());
  console.log("Pesan setelah didekripsi:", decrypted);
});

// ============================================================
// ============================================================

// ============================================================
// ============================================================
