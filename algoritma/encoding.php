<?php
/**
 * ============================================
 *  DEMO ENCODING & DECODING DALAM PHP
 *  --------------------------------------------
 *  Contoh sederhana:
 *  1. Base64 Encoding
 *  2. URL Encoding
 *  3. JSON Encoding
 *  4. Unicode Encoding
 * ============================================
 */

echo "<h2 style='font-family:Segoe UI;color:#007bff;'>Demo Encoding & Decoding dalam PHP</h2>";

/* =========================================================
 * 1. BASE64 ENCODING
 *    - Mengubah data biner menjadi teks ASCII
 *    - Umum digunakan untuk kirim data di email, JSON, API
 * ========================================================= */
echo "<h3>1️⃣ Base64 Encoding & Decoding</h3><pre>";
echo "<h3>Mengubah file biner jadi teks agar bisa dikirim lewat email/JSON</h3><pre>";


$originalData = "2321500018 (Nomor Induk Mahasiswa)";
$startTime = microtime(true);
$encoded = base64_encode($originalData);
$endTime = microtime(true);
$decoded = base64_decode($encoded);

$originalSize = strlen($originalData);
$encodedSize = strlen($encoded);

$duration = $endTime - $startTime;

echo "<b>Original:</b> $originalData\n";
echo "<b>Encoded:</b> $encoded\n";
echo "<b>Waktu Proses Encode:</b> " . number_format($duration, 6) . " detik\n";
echo "<b>Decoded:</b> $decoded\n";

echo "<b>Size Data Original:</b> $originalSize bytes\n";
echo "<b>Size Data Encoded:</b> $encodedSize bytes\n";
echo "</pre>";

/* =========================================================
 * 2. URL ENCODING
 *    - Mengubah karakter khusus agar aman di URL
 *    - Contoh: spasi menjadi %20
 * ========================================================= */
echo "<h3>2️⃣ URL Encoding & Decoding</h3><pre>";
echo "<h3>Mengubah karakter khusus jadi aman di URL</h3><pre>";

$url = "https://example.com/search?q=hello world&lang=id";
$startTime_url = microtime(true);
$encoded_url = urlencode($url);
$endTime_url = microtime(true);
$duration_url = $endTime_url - $startTime_url;
$decoded_url = urldecode($encoded_url);

$originalSize_url = strlen($url);
$encodedSize_url = strlen($encoded_url);

echo "<b>Original URL:</b> $url\n";
echo "<b>Encoded URL:</b> $encoded_url\n";
echo "<b>Waktu Proses Encode URL:</b> " . number_format($duration_url, 6) . " detik\n";
echo "<b>Decoded URL:</b> $decoded_url\n";

echo "<b>Size URL Original:</b> $originalSize_url bytes\n";
echo "<b>Size URL Encoded:</b> $encodedSize_url bytes\n";
echo "</pre>";

/* =========================================================
 * 3. JSON ENCODING
 *    - Mengubah array/objek PHP menjadi format JSON
 *    - JSON sering dipakai untuk komunikasi antar sistem
 * ========================================================= */
echo "<h3>3️⃣ JSON Encoding & Decoding</h3><pre>";
$data = [
    [
        'name'  => 'John Doe',
    'email' => 'john@example.com',
    'age'   => 30
    ],
    [
        'name'  => 'John Doe',
        'email' => 'john@example.com',
        'age'   => 30
    ]
];
$startTime_json = microtime(true);
$json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
$endTime_json = microtime(true);
$decoded_json = json_decode($json, true);
$duration_json = $endTime_json - $startTime_json;

$originalSize_json = strlen(serialize($data));
$encodedSize_json = strlen($json);

echo "<b>JSON Encoded:</b>\n$json\n";
echo "<b>Waktu Proses Encode JSON:</b> " . number_format($duration_json, 6) . " detik\n";
echo "<b>JSON Decoded (Array):</b>\n";
print_r($decoded_json);

echo "<b>Size Data Original:</b> $originalSize_json bytes\n";
echo "<b>Size JSON Encoded:</b> $encodedSize_json bytes\n";
echo "</pre>";

/* =========================================================
 * 4. UNICODE ENCODING
 *    - Menangani karakter multibahasa (contoh: 中文, العربية)
 *    - UTF-8 menjaga agar karakter tampil benar di seluruh dunia
 * ========================================================= */
echo "<h3>4️⃣ Unicode Encoding & Decoding (UTF-8)</h3><pre>";
echo "<h3>Representasi karakter dari berbagai bahasa di dunia</h3><pre>";

$unicodeString = "Hello, 世界"; 
$startTime_unicode = microtime(true); 
$encodedUnicode = bin2hex(mb_convert_encoding($unicodeString, 'UTF-8', 'UTF-8'));
$endTime_unicode = microtime(true);
$decodedUnicode = mb_convert_encoding(hex2bin($encodedUnicode), 'UTF-8', 'UTF-8');
$duration_unicode = $endTime_unicode - $startTime_unicode;

$originalSize_unicode = strlen($unicodeString);
$encodedSize_unicode = strlen($encodedUnicode);

echo "<b>Original Unicode:</b> $unicodeString\n";
echo "<b>Hex Encoded UTF-8:</b> $encodedUnicode\n";
echo "<b>Waktu Proses Encode Unicode:</b> " . number_format($duration_unicode, 6) . " detik\n";
echo "<b>Decoded Unicode:</b> $decodedUnicode\n";

echo "<b>Size Data Original:</b> $originalSize_unicode bytes\n";
echo "<b>Size Data Encoded:</b> $encodedSize_unicode bytes\n";
echo "</pre>";

echo "<hr><small style='color:gray;'>PHP Encoding Demo – © 2025</small>";
?>
