<?php

/**
 * ============================================
 *  DEMO ENKRIPSI DALAM PHP
 *  --------------------------------------------
 *  1. Symmetric Encryption (AES-256-CBC)
 *  2. Asymmetric Encryption (RSA)
 * ============================================
 */

echo "<h2 style='font-family:Segoe UI;color:#007bff;'>Demo Enkripsi dalam PHP</h2>";
echo "<h3>Enkripsi adalah proses mengubah data asli (plaintext) menjadi data terenkripsi (ciphertext) menggunakan kunci (key) dan algoritma tertentu.
➡️ Bisa dikembalikan (dua arah) dengan kunci yang benar.</h3><pre>";

$plaintext = "Data rahasia penting 🕵️‍♂️";
echo "<p><b>Teks Asli:</b> $plaintext</p>";

/* =========================================================
 * 1️⃣ SYMMETRIC ENCRYPTION (AES-256-CBC)
 *    - Menggunakan satu kunci yang sama untuk enkripsi & dekripsi.
 *    - Cepat dan umum digunakan untuk enkripsi data lokal atau file.
 * ========================================================= */
echo "<h3>1️⃣ Symmetric Encryption (AES-256-CBC)</h3><pre>";

// Buat kunci rahasia dan inisialisasi IV (Initialization Vector)
$key = openssl_random_pseudo_bytes(32); // 256-bit key
$iv  = openssl_random_pseudo_bytes(16); // 128-bit IV

// Enkripsi
$startTime_aes = microtime(true);
$encrypted = openssl_encrypt($plaintext, 'AES-256-CBC', $key, 0, $iv);
$endTime_aes = microtime(true);
$duration_aes = $endTime_aes - $startTime_aes;
// Dekripsi
$decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, $iv);

$originalSize_aes = strlen($plaintext);
$encryptedSize_aes = strlen($encrypted);

echo "<b>Algoritma:</b> AES-256-CBC\n";
echo "<b>Kunci (hex):</b> " . bin2hex($key) . "\n";
echo "<b>IV (hex):</b> " . bin2hex($iv) . "\n\n";
echo "<b>Teks terenkripsi (base64):</b> $encrypted\n";
echo "<b>Waktu Proses Enkripsi AES:</b> " . number_format($duration_aes, 6) . " detik\n";
echo "<b>Hasil dekripsi:</b> $decrypted\n";

echo "<b>Size Data Original:</b> $originalSize_aes bytes\n";
echo "<b>Size Data Encrypted:</b> $encryptedSize_aes bytes\n";
echo "</pre>";

/* =========================================================
 * 2️⃣ ASYMMETRIC ENCRYPTION (RSA)
 *    - Menggunakan dua kunci berbeda:
 *        * Public key: untuk enkripsi
 *        * Private key: untuk dekripsi
 *    - Umum digunakan dalam SSL, tanda tangan digital, dan token.
 * ========================================================= */
echo "<h3>2️⃣ Asymmetric Encryption (RSA)</h3><pre>";
//url untuk generate keypair RSA 2048-bit:https://cryptotools.net/rsagen

// Lokasi file kunci
$privateKeyPath = __DIR__ . '/rsa/private.key';
$publicKeyPath  = __DIR__ . '/rsa/public.key';

// Baca kunci dari file
$privateKey = file_get_contents($privateKeyPath);
$publicKey  = file_get_contents($publicKeyPath);

if ($privateKey === false || $publicKey === false) {
    echo "<b style='color:red;'>Gagal membaca file kunci RSA.</b>\n";
} else {
    // Enkripsi menggunakan public key
    $startEncrypt = microtime(true);
    if (openssl_public_encrypt($plaintext, $encryptedRSA, $publicKey)) {
        $endEncrypt = microtime(true);
        $durationEncrypt = $endEncrypt - $startEncrypt;
        $originalSize = strlen($plaintext);
        $encryptedSize = strlen($encryptedRSA);
        // Dekripsi menggunakan private key
        if (openssl_private_decrypt($encryptedRSA, $decryptedRSA, $privateKey)) {
            echo "<b>Algoritma:</b> RSA-2048\n";
            echo "<b>Public Key:</b>\n" . htmlspecialchars($publicKey) . "\n";
            echo "<b>Private Key:</b>\n" . htmlspecialchars($privateKey) . "\n";
            echo "<b>Teks terenkripsi (base64):</b> " . base64_encode($encryptedRSA) . "\n";
            echo "<b>Waktu Proses Enkripsi RSA:</b> " . number_format($durationEncrypt, 6) . " detik\n";
            echo "<b>Size Data Original:</b> $originalSize bytes\n";
            echo "<b>Size Data Encrypted:</b> $encryptedSize bytes\n";
            echo "<b>Hasil dekripsi:</b> $decryptedRSA\n";
        } else {
            echo "<b style='color:red;'>Gagal mendekripsi data dengan private key.</b>\n";
        }
    } else {
        echo "<b style='color:red;'>Gagal mengenkripsi data dengan public key.</b>\n";
    }
}
echo "</pre>";

echo "<hr><small style='color:gray;'>PHP Encryption Demo – © 2025</small>";
