const fs = require("fs");
const Encryption = require("./encryption");

const encryption = new Encryption();

const message = "mantap...";
const encrypted = encryption.encodeWithSecret(message);
console.log({ encrypted });
const decrypted = encryption.decodeWithSecret(encrypted);
console.log({ decrypted });

// Baca isi file encrypted.txt
fs.readFile("encrypted.txt", "utf8", (err, data) => {
  if (err) {
    console.error("Gagal membaca file:", err);
    return;
  }

  // Dekripsi isi file
  const decrypted = encryption.decodeWithSecret(data.trim());
  console.log("Pesan setelah didekripsi:", decrypted);
});
