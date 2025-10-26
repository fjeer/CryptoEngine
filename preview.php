<?php
/**
 * PREVIEW.PHP - File Preview Handler
 */

require_once 'config.php';

$file = isset($_GET['file']) ? $_GET['file'] : '';
$file = basename($file);

if (empty($file)) {
    http_response_code(400);
    die('Invalid filename');
}

$filePath = PREVIEW_DIR . '/' . $file;

if (!file_exists($filePath)) {
    http_response_code(404);
    die('Preview file not found');
}

$fileSize = filesize($filePath);
$previewInfo = canPreviewFile($file);

if (!$previewInfo['can_preview']) {
    http_response_code(403);
    die('File type cannot be previewed');
}

$mimeType = getMimeType($filePath);
header('Content-Type: ' . $mimeType);
header('Content-Length: ' . $fileSize);
header('Content-Disposition: inline; filename="' . $file . '"');
header('Cache-Control: private, max-age=3600');
header('X-Content-Type-Options: nosniff');

readfile($filePath);
exit;
?>
