<?php
echo "<h2 style='font-family:Segoe UI;color:#007bff;'>Tugas Encoding, Hashing, Encrypting</h2>";

$plaintext = "2321500018 (Nomor Induk Mahasiswa)";
$originalSize = strlen($plaintext);
echo "<p><b>Teks Asli:</b> $plaintext</p>";
echo "<p><b>Ukuran Teks Asli:</b> $originalSize bytes</p>";

/* ============================================================
   1️⃣ HYBRID ENCRYPTION (AES + RSA)
============================================================ */
echo "<h3>1️⃣ Hybrid AES & RSA</h3><pre>";

// === AES ENCRYPTION ===
$aes_key = openssl_random_pseudo_bytes(32); // 256-bit key
$iv = openssl_random_pseudo_bytes(16);      // 128-bit IV

$startEncrypt = microtime(true);
$encrypted_data = openssl_encrypt($plaintext, 'AES-256-CBC', $aes_key, OPENSSL_RAW_DATA, $iv);
$endEncrypt = microtime(true);
$durationEncrypt = $endEncrypt - $startEncrypt;
$sizeEncryptedData = strlen($encrypted_data);

echo "Waktu Enkripsi AES: " . number_format($durationEncrypt, 6) . " detik\n";
echo "Kunci AES (hex): " . bin2hex($aes_key) . "\n";
echo "IV (hex): " . bin2hex($iv) . "\n";
echo "Teks Enkripsi (base64): " . base64_encode($encrypted_data) . "\n";
echo "Ukuran Teks Enkripsi: " . $sizeEncryptedData . " bytes\n";

echo "<hr>";

// === RSA ENCRYPTION ===
$privateKeyPath = __DIR__ . '/rsa/private.key';
$publicKeyPath = __DIR__ . '/rsa/public.key';

$privateKey = file_get_contents($privateKeyPath);
$publicKey = file_get_contents($publicKeyPath);

if (!$privateKey || !$publicKey) {
    echo "<b style='color:red;'>Gagal membaca file kunci RSA!</b>\n";
    exit;
}

// Enkripsi AES key dengan RSA public key
$startRSA = microtime(true);
if (openssl_public_encrypt($aes_key, $encrypted_key, $publicKey)) {
    $endRSA = microtime(true);
    $rsaTime = $endRSA - $startRSA;
    echo "Kunci AES terenkripsi (Base64): " . base64_encode($encrypted_key) . "\n";
    echo "Waktu Enkripsi RSA: " . number_format($rsaTime, 6) . " detik\n";
} else {
    echo "<b style='color:red;'>Gagal mengenkripsi kunci AES dengan RSA!</b>\n";
    exit;
}

echo "<hr>";

// === DECRYPTION ===
if (openssl_private_decrypt($encrypted_key, $decrypted_aes_key, $privateKey)) {
    $decrypted_text = openssl_decrypt($encrypted_data, 'AES-256-CBC', $decrypted_aes_key, OPENSSL_RAW_DATA, $iv);
    echo "Hasil Dekripsi: $decrypted_text\n";
} else {
    echo "<b style='color:red;'>Gagal mendekripsi kunci AES dengan RSA!</b>\n";
}

echo "<hr>";


/* ============================================================
   2️⃣ AES-256-CBC (tanpa password, key random)
============================================================ */
echo "<h3>2️⃣ Enkripsi AES-256-CBC</h3><pre>";

$key = random_bytes(32); // 256-bit key
$iv = random_bytes(16); // 128-bit IV

$start = microtime(true);
$encrypted = openssl_encrypt($plaintext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
$end = microtime(true);
$sizeEncryptedData = strlen($encrypted);

$decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
$time = $end - $start;

echo "Kunci (hex): " . bin2hex($key) . "\n";
echo "IV (hex): " . bin2hex($iv) . "\n";
echo "Teks Enkripsi (base64): " . base64_encode($encrypted) . "\n";
echo "Waktu Enkripsi: " . number_format($time, 6) . " detik\n";
echo "Ukuran Teks Enkripsi: " . $sizeEncryptedData . " bytes\n";
echo "Hasil Dekripsi: $decrypted\n";

echo "<hr>";


/* ============================================================
   3️⃣ AES-256-GCM (tanpa password, key random)
============================================================ */
echo "<h3>3️⃣ Enkripsi AES-256-GCM</h3><pre>";

$key = random_bytes(32); // 256-bit key
$iv = random_bytes(12); // 96-bit IV (standar GCM)
$aad = "metadata";

$start = microtime(true);
$cipher = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, $aad);
$end = microtime(true);
$sizeEncryptedData = strlen($cipher);

$decrypted = openssl_decrypt($cipher, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, $aad);
$time = $end - $start;

echo "Kunci (hex): " . bin2hex($key) . "\n";
echo "IV (hex): " . bin2hex($iv) . "\n";
echo "Auth Tag (hex): " . bin2hex($tag) . "\n";
echo "Teks Enkripsi (base64): " . base64_encode($cipher) . "\n";
echo "Waktu Enkripsi AES-GCM: " . number_format($time, 6) . " detik\n";
echo "Ukuran Teks Enkripsi: " . $sizeEncryptedData . " bytes\n";
echo "Hasil Dekripsi: $decrypted\n";

echo "<hr>";


/* ============================================================
   4️⃣ Camellia-256-CBC (tanpa password, key random)
============================================================ */
echo "<h3>4️⃣ Enkripsi Camellia-256-CBC</h3><pre>";

$key = random_bytes(32); // 256-bit key
$iv = random_bytes(16); // 128-bit IV

$start = microtime(true);
$cipher_cam = openssl_encrypt($plaintext, 'camellia-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
$end = microtime(true);
$sizeEncryptedData = strlen($cipher_cam);

$decrypted_cam = openssl_decrypt($cipher_cam, 'camellia-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
$time = $end - $start;

echo "Kunci (hex): " . bin2hex($key) . "\n";
echo "IV (hex): " . bin2hex($iv) . "\n";
echo "Teks Enkripsi (base64): " . base64_encode($cipher_cam) . "\n";
echo "Waktu Enkripsi Camellia: " . number_format($time, 6) . " detik\n";
echo "Ukuran Teks Enkripsi: " . $sizeEncryptedData . " bytes\n";
echo "Hasil Dekripsi: $decrypted_cam\n";

echo "<h3>5️⃣ Enkripsi RSA</h3><pre>";

// Lokasi file kunci
$privateKeyPath = __DIR__ . '/rsa/private.key';
$publicKeyPath = __DIR__ . '/rsa/public.key';

// Baca kunci dari file
$privateKey = file_get_contents($privateKeyPath);
$publicKey = file_get_contents($publicKeyPath);

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