<?php
/**
 * ======================================================
 * DEMO HYBRID ENCRYPTION (AES + RSA)
 * --------------------------------------
 * - AES-256-CBC → Enkripsi data cepat (symmetric)
 * - RSA-2048 → Enkripsi kunci AES (asymmetric)
 * ======================================================
 */


echo "<h2 style='font-family:Segoe UI;color:#007bff;'>🔐 Demo Hybrid Encryption (AES + RSA)</h2>";


$plaintext = "Data rahasia sangat penting 🕵️‍♂️";
echo "<p><b>Teks Asli:</b> $plaintext</p>";


/* =========================================================
 * 1️⃣ LANGKAH 1: Enkripsi data dengan AES
 * ========================================================= */
echo "<h3>1️⃣ Enkripsi Data (AES-256-CBC)</h3><pre>";


// Generate AES key dan IV
$aes_key = openssl_random_pseudo_bytes(32); // 256-bit key
$iv      = openssl_random_pseudo_bytes(16); // 128-bit IV


// Enkripsi plaintext
$startEncrypt = microtime(true);
$encrypted_data = openssl_encrypt($plaintext, 'AES-256-CBC', $aes_key, OPENSSL_RAW_DATA, $iv);
$endEncrypt = microtime(true);
$durationEncrypt = $endEncrypt - $startEncrypt;

$originalSize = strlen($plaintext);
$encryptedSize = strlen($encrypted_data);


echo "<b>Algoritma:</b> AES-256-CBC\n";
echo "<b>Kunci AES (hex):</b> " . bin2hex($aes_key) . "\n";
echo "<b>IV (hex):</b> " . bin2hex($iv) . "\n";
echo "<b>Data terenkripsi (base64):</b> " . base64_encode($encrypted_data) . "\n";
echo "<b>Waktu Proses Enkripsi AES:</b> " . number_format($durationEncrypt, 6) . " detik\n";
echo "<b>Size Data Original:</b> $originalSize bytes\n";
echo "<b>Size Data Encrypted:</b> $encryptedSize bytes\n";
echo "</pre>";


/* =========================================================
 * 2️⃣ LANGKAH 2: Enkripsi kunci AES dengan RSA
 * ========================================================= */
echo "<h3>2️⃣ Enkripsi Kunci AES (RSA-2048)</h3><pre>";


// Path ke file kunci
$privateKeyPath = __DIR__ . '/rsa/private.key';
$publicKeyPath  = __DIR__ . '/rsa/public.key';


// Baca kunci dari file
$privateKey = file_get_contents($privateKeyPath);
$publicKey  = file_get_contents($publicKeyPath);


if ($privateKey === false || $publicKey === false) {
	echo "<b style='color:red;'>Gagal membaca file RSA key.</b>\n";
	exit;
}


// Enkripsi kunci AES dengan public key
if (openssl_public_encrypt($aes_key, $encrypted_key, $publicKey)) {
	echo "<b>Public Key (RSA-2048):</b> OK\n";
	echo "<b>Kunci AES terenkripsi (base64):</b> " . base64_encode($encrypted_key) . "\n";
} else {
	echo "<b style='color:red;'>Gagal mengenkripsi kunci AES dengan RSA.</b>\n";
	exit;
}


/* =========================================================
 * 3️⃣ LANGKAH 3: Dekripsi kunci AES & data
 * ========================================================= */
echo "<h3>3️⃣ Dekripsi Data</h3><pre>";


// Dekripsi kunci AES
if (openssl_private_decrypt($encrypted_key, $decrypted_aes_key, $privateKey)) {
	// Dekripsi data dengan AES key hasil dekripsi
	$decrypted_text = openssl_decrypt($encrypted_data, 'AES-256-CBC', $decrypted_aes_key, OPENSSL_RAW_DATA, $iv);

	echo "<b>Kunci AES hasil dekripsi (hex):</b> " . bin2hex($decrypted_aes_key) . "\n";
	echo "<b>Hasil dekripsi:</b> $decrypted_text\n";
} else {
	echo "<b style='color:red;'>Gagal mendekripsi kunci AES dengan private key.</b>\n";
}
echo "</pre>";


echo "<hr><small style='color:gray;'>© 2025 Hybrid Encryption Demo – AES + RSA</small>";
?>