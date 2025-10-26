<?php

/**
 * DOWNLOAD.PHP - Secure File Download Handler
 */

require_once 'config.php';

$dir = isset($_GET['dir']) ? $_GET['dir'] : '';
$file = isset($_GET['file']) ? $_GET['file'] : '';

$allowedDirs = ['encrypted', 'decrypted', 'preview'];
if (!in_array($dir, $allowedDirs)) {
    http_response_code(403);
    die('Access denied');
}

$file = basename($file);
if (empty($file)) {
    http_response_code(400);
    die('Invalid filename');
}

$dirPath = BASE_PATH . '/' . $dir;
$filePath = $dirPath . '/' . $file;

if (!file_exists($filePath)) {
    http_response_code(404);
    die('File not found');
}

$fileSize = filesize($filePath);
$fileExt = strtolower(pathinfo($file, PATHINFO_EXTENSION));

$mimeTypes = [
    'txt' => 'text/plain',
    'pdf' => 'application/pdf',
    'jpg' => 'image/jpeg',
    'jpeg' => 'image/jpeg',
    'png' => 'image/png',
    'gif' => 'image/gif',
    'webp' => 'image/webp',
    'enc' => 'application/octet-stream',
    'json' => 'application/json'
];

$mimeType = isset($mimeTypes[$fileExt]) ? $mimeTypes[$fileExt] : 'application/octet-stream';

$inlineTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'application/pdf', 'text/plain'];
$disposition = in_array($mimeType, $inlineTypes) ? 'inline' : 'attachment';

header('Content-Type: ' . $mimeType);
header('Content-Length: ' . $fileSize);
header('Content-Disposition: ' . $disposition . '; filename="' . $file . '"');
header('Cache-Control: private, max-age=3600');
header('X-Content-Type-Options: nosniff');

readfile($filePath);
exit;
