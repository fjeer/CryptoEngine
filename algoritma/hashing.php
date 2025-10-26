<?php

/**
 * ============================================
 *  DEMO HASHING ALGORITMA DALAM PHP
 *  --------------------------------------------
 *  1. MD5 (128-bit)
 *  2. SHA-1 (160-bit)
 *  3. SHA-256 / SHA-512 (SHA-2 Family)
 *  4. Bcrypt (Password Hashing)
 * ============================================
 */

echo "<h2 style='font-family:Segoe UI;color:#007bff;'>Demo Hashing Algoritma dalam PHP</h2>";
echo "<h3>Hashing adalah proses satu arah (one-way) yang mengubah data dengan panjang apa pun menjadi kode unik dengan panjang tetap.

➡️ Hash tidak bisa diubah kembali ke data aslinya.

🔹 Tujuan  

Mengecek integritas data (apakah file berubah/tidak).

Menyimpan password dengan aman di database.</h3><pre>";
$password = "2321500018 (Nomor Induk Mahasiswa)"; // contoh input teks
echo "<p><b>Teks Asli:</b> $password</p>";

/* =========================================================
 * 1️⃣ MD5 (Message Digest 5)
 *    - Hash 128-bit (32 karakter hex)
 *    - Cepat, tapi tidak aman untuk password
 *    - Masih berguna untuk checksum file non-sensitif
 * ========================================================= */
echo "<h3>1️⃣ MD5 (128-bit)</h3><pre>";
$startTime_md5 = microtime(true);
$md5 = md5($password);
$endTime_md5 = microtime(true);
$duration_md5 = $endTime_md5 - $startTime_md5;
$originalSize_md5 = strlen($password);
echo "<b>MD5 Hash:</b> $md5\n";
echo "<b>Waktu Proses Hash MD5:</b> " . number_format($duration_md5, 6) . " detik\n";
echo "<b>Size Data Original:</b> $originalSize_md5 bytes\n";
echo "<b>Panjang hash:</b> " . strlen($md5) . " karakter\n";
echo "</pre>";

/* =========================================================
 * 2️⃣ SHA-1 (Secure Hash Algorithm 1)
 *    - Hash 160-bit (40 karakter hex)
 *    - Sudah tidak direkomendasikan untuk keamanan
 * ========================================================= */
echo "<h3>2️⃣ SHA-1 (160-bit)</h3><pre>";
$startTime_sha1 = microtime(true);
$sha1 = sha1($password);
$endTime_sha1 = microtime(true);
$duration_sha1 = $endTime_sha1 - $startTime_sha1;
$originalSize_sha1 = strlen($password);
echo "<b>SHA-1 Hash:</b> $sha1\n";
echo "<b>Waktu Proses Hash SHA-1:</b> " . number_format($duration_sha1, 6) . " detik\n";
echo "<b>Size Data Original:</b> $originalSize_sha1 bytes\n";
echo "<b>Panjang hash:</b> " . strlen($sha1) . " karakter\n";
echo "</pre>";

/* =========================================================
 * 3️⃣ SHA-256 dan SHA-512 (Bagian dari SHA-2)
 *    - SHA-256 menghasilkan 64 karakter hex (256-bit)
 *    - SHA-512 menghasilkan 128 karakter hex (512-bit)
 *    - Direkomendasikan untuk integritas data dan keamanan modern
 * ========================================================= */
echo "<h3>3️⃣ SHA-256 & SHA-512 (SHA-2 Family)</h3><pre>";
$startTime_sha256 = microtime(true);
$sha256 = hash('sha256', $password);
$endTime_sha256 = microtime(true);
$duration_sha256 = $endTime_sha256 - $startTime_sha256;
$originalSize_sha256 = strlen($password);
$startTime_sha512 = microtime(true);
$sha512 = hash('sha512', $password);
$endTime_sha512 = microtime(true);
$duration_sha512 = $endTime_sha512 - $startTime_sha512;
$originalSize_sha512 = strlen($password);

echo "<b>SHA-256 Hash:</b> $sha256\n";
echo "<b>Waktu Proses Hash SHA-256:</b> " . number_format($duration_sha256, 6) . " detik\n";
echo "<b>Size Data Original:</b> $originalSize_sha256 bytes\n";
echo "<b>Panjang hash:</b> " . strlen($sha256) . " karakter\n\n";
echo "<b>SHA-512 Hash:</b> $sha512\n";
echo "<b>Waktu Proses Hash SHA-512:</b> " . number_format($duration_sha512, 6) . " detik\n";
echo "<b>Size Data Original:</b> $originalSize_sha512 bytes\n";
echo "<b>Panjang hash:</b> " . strlen($sha512) . " karakter\n";
echo "</pre>";

/* =========================================================
 * 4️⃣ Bcrypt
 *    - Algoritma modern khusus untuk password
 *    - Ada built-in salt + cost factor (default cost: 10)
 *    - Hasil berbeda setiap kali walau input sama
 * ========================================================= */
echo "<h3>4️⃣ Bcrypt (Password Hashing)</h3><pre>";
$startTime_bcrypt = microtime(true);
$bcrypt = password_hash($password, PASSWORD_BCRYPT);
$endTime_bcrypt = microtime(true);
$duration_bcrypt = $endTime_bcrypt - $startTime_bcrypt;
$originalSize_bcrypt = strlen($password);
$bcrypt_size = strlen($bcrypt);
echo "<b>Bcrypt Hash:</b> $bcrypt\n";
echo "<b>Verifikasi:</b> ";
echo password_verify($password, $bcrypt) ? "✅ Cocok\n" : "❌ Tidak cocok\n";
echo "<b>Waktu Proses Hash Bcrypt:</b> " . number_format($duration_bcrypt, 6) . " detik\n";
echo "<b>Size Data Original:</b> $originalSize_bcrypt bytes\n";
echo "<b>Panjang hash:</b> $bcrypt_size karakter\n";
echo "</pre>";

echo "<hr><small style='color:gray;'>PHP Hashing Demo – © 2025</small>";
