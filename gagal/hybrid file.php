<?php
echo "<h2 style='font-family:Segoe UI;color:#007bff;'>🔐 Tugas Enkripsi & Dekripsi File Lokal</h2>";

/* ============================================================
   🗂️ Konfigurasi File
============================================================ */
$inputFile = __DIR__ . '/e-ktm.png';      // file yang mau dienkripsi
$encFile = __DIR__ . '/e-ktm.enc';      // hasil enkripsi
$decFile = __DIR__ . '/e-ktm.dec.png';  // hasil dekripsi

// if (!file_exists($inputFile)) {
//     file_put_contents($inputFile, "2321500018 (Nomor Induk Mahasiswa)\nContoh isi file untuk enkripsi.");
//     echo "<p><b>File sample.txt</b> dibuat otomatis karena belum ada.</p>";
// }

$plaintext = file_get_contents($inputFile);
$originalSize = strlen($plaintext);
echo "<p><b>File asli:</b> e-ktm.png</p>";
echo "<p><b>Ukuran file asli:</b> " . number_format($originalSize / 1024, 2) . " KB</p>";

/* ============================================================
   🔐 Load RSA Key (sudah ada di folder /rsa)
============================================================ */
$privateKeyPath = __DIR__ . '/rsa/private.key';
$publicKeyPath = __DIR__ . '/rsa/public.key';

$privateKey = file_get_contents($privateKeyPath);
$publicKey = file_get_contents($publicKeyPath);

if (!$privateKey || !$publicKey) {
    die("<b style='color:red;'>❌ File kunci RSA tidak ditemukan di folder /rsa</b>");
}

/* ============================================================
   1️⃣ Hybrid Encryption (AES + RSA)
============================================================ */
echo "<h3>1️⃣ Hybrid AES-256-CBC + RSA</h3><pre>";

$aes_key = random_bytes(32); // 256-bit key
$iv = random_bytes(16);      // 128-bit IV

$startEncrypt = microtime(true);
$encryptedData = openssl_encrypt($plaintext, 'AES-256-CBC', $aes_key, OPENSSL_RAW_DATA, $iv);
$endEncrypt = microtime(true);
$timeEncrypt = $endEncrypt - $startEncrypt;
$sizeEncryptedData = strlen($encryptedData);

// Enkripsi AES key pakai RSA
openssl_public_encrypt($aes_key, $encryptedKey, $publicKey);

// Gabungkan IV + RSA-encrypted key + data terenkripsi
$finalData = $iv . $encryptedKey . $encryptedData;
file_put_contents($encFile, $finalData);

echo "✅ File terenkripsi disimpan: .enc\n";
echo "Waktu Enkripsi: " . number_format($timeEncrypt, 6) . " detik\n";
echo "Ukuran File Enkripsi: " . number_format(filesize($encFile) / 1024, 2) . " KB\n";
echo "Kunci AES (hex): " . bin2hex($aes_key) . "\n";
echo "IV (hex): " . bin2hex($iv) . "\n";

echo "<hr>";

/* ============================================================
   2️⃣ Dekripsi File
============================================================ */

$encryptedFileData = file_get_contents($encFile);

// Pisahkan data (IV + RSA-encrypted-key + encrypted-data)
$iv = substr($encryptedFileData, 0, 16);
$encryptedKey = substr($encryptedFileData, 16, 256); // panjang RSA-2048 hasil encrypt = 256 byte
$encryptedData = substr($encryptedFileData, 272);    // sisanya adalah ciphertext

// Dekripsi AES key pakai RSA private key
openssl_private_decrypt($encryptedKey, $decryptedKey, $privateKey);

// Dekripsi data pakai AES key hasil dekripsi
$startDecrypt = microtime(true);
$decryptedText = openssl_decrypt($encryptedData, 'AES-256-CBC', $decryptedKey, OPENSSL_RAW_DATA, $iv);
$endDecrypt = microtime(true);
$timeDecrypt = $endDecrypt - $startDecrypt;

// Simpan hasil dekripsi
file_put_contents($decFile, $decryptedText);

echo "✅ File hasil dekripsi disimpan: .dec.txt\n";
echo "Waktu Dekripsi: " . number_format($timeDecrypt, 6) . " detik\n";
echo "Ukuran File Dekripsi: " . number_format(filesize($decFile) / 1024, 2) . " KB\n";
echo "Isi File Hasil Dekripsi:" . base64_encode($decryptedText) . "\n";
echo "</pre>";

/* ============================================================
============================================================ */
echo "<hr><h3>📊 Ringkasan</h3>";
echo "<p><b>File Asli:</b> " . basename($inputFile) . " (" . number_format(filesize($inputFile) / 1024, 2) . " KB)</p>";
echo "<p><b>File Enkripsi:</b> " . basename($encFile) . " (" . number_format(filesize($encFile) / 1024, 2) . " KB)</p>";
echo "<p><b>File Dekripsi:</b> " . basename($decFile) . " (" . number_format(filesize($decFile) / 1024, 2) . " KB)</p>";

echo "<h3>2️⃣ Enkripsi File</h3><pre>";

