<?php

/**
 * CRYPTO SYSTEM - Configuration File
 * Version: 2.0
 * PHP >= 7.4 Required
 */

// Error reporting
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/error.log');

// Session
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Paths
define('BASE_PATH', __DIR__);
define('KEYS_DIR', BASE_PATH . '/keys');
define('UPLOADS_DIR', BASE_PATH . '/uploads');
define('ENCRYPTED_DIR', BASE_PATH . '/encrypted');
define('DECRYPTED_DIR', BASE_PATH . '/decrypted');
define('PREVIEW_DIR', BASE_PATH . '/preview');

// Settings
define('MAX_FILE_SIZE', 10 * 1024 * 1024); // 10 MB
define('PREVIEW_TYPES', [
    'image' => ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp'],
    'pdf' => ['pdf'],
    'text' => ['txt', 'log', 'json', 'xml', 'csv', 'md', 'html', 'css', 'js', 'php']
]);

// Timezone
date_default_timezone_set('Asia/Jakarta');

// Create directories
$requiredDirs = [KEYS_DIR, UPLOADS_DIR, ENCRYPTED_DIR, DECRYPTED_DIR, PREVIEW_DIR];
foreach ($requiredDirs as $dir) {
    if (!is_dir($dir)) {
        if (!mkdir($dir, 0755, true)) {
            die("Failed to create directory: {$dir}");
        }
        chmod($dir, 0755);
    }
    if (!is_writable($dir)) {
        die("Directory not writable: {$dir}. Run: chmod 755 {$dir}");
    }
}

/**
 * System Requirements Check
 */
function checkSystemRequirements()
{
    return [
        'php_version' => [
            'check' => version_compare(PHP_VERSION, '7.4.0', '>='),
            'current' => PHP_VERSION,
            'required' => '7.4.0',
            'critical' => true
        ],
        'openssl' => [
            'check' => extension_loaded('openssl'),
            'description' => 'WAJIB - Untuk enkripsi/dekripsi',
            'critical' => true
        ],
        'curl' => [
            'check' => extension_loaded('curl'),
            'description' => 'WAJIB - Generate RSA keys',
            'critical' => true
        ],
        'mbstring' => [
            'check' => extension_loaded('mbstring'),
            'description' => 'WAJIB - String handling',
            'critical' => true
        ],
        'fileinfo' => [
            'check' => extension_loaded('fileinfo'),
            'description' => 'Recommended - MIME detection',
            'critical' => false
        ]
    ];
}

/**
 * Format file size
 */
function formatFileSize($bytes)
{
    if ($bytes >= 1073741824) {
        return number_format($bytes / 1073741824, 2) . ' GB';
    } elseif ($bytes >= 1048576) {
        return number_format($bytes / 1048576, 2) . ' MB';
    } elseif ($bytes >= 1024) {
        return number_format($bytes / 1024, 2) . ' KB';
    }
    return $bytes . ' bytes';
}

/**
 * Get file extension
 */
function getFileExtension($filename)
{
    return strtolower(pathinfo($filename, PATHINFO_EXTENSION));
}

/**
 * Check preview capability
 */
function canPreviewFile($filename)
{
    $ext = getFileExtension($filename);
    foreach (PREVIEW_TYPES as $type => $extensions) {
        if (in_array($ext, $extensions)) {
            return ['can_preview' => true, 'type' => $type];
        }
    }
    return ['can_preview' => false, 'type' => null];
}

/**
 * Get MIME type
 */
function getMimeType($filename)
{
    if (file_exists($filename) && function_exists('finfo_open')) {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        if ($finfo) {
            $mimeType = finfo_file($finfo, $filename);
            finfo_close($finfo);
            if ($mimeType) return $mimeType;
        }
    }

    if (function_exists('mime_content_type')) {
        $mimeType = @mime_content_type($filename);
        if ($mimeType) return $mimeType;
    }

    $ext = getFileExtension($filename);
    $map = [
        'txt' => 'text/plain',
        'html' => 'text/html',
        'json' => 'application/json',
        'xml' => 'application/xml',
        'csv' => 'text/csv',
        'jpg' => 'image/jpeg',
        'jpeg' => 'image/jpeg',
        'png' => 'image/png',
        'gif' => 'image/gif',
        'bmp' => 'image/bmp',
        'webp' => 'image/webp',
        'pdf' => 'application/pdf'
    ];

    return $map[$ext] ?? 'application/octet-stream';
}

/**
 * Error logging
 */
function logError($context, $message, $data = [])
{
    $timestamp = date('Y-m-d H:i:s');
    $logMessage = "{$timestamp} [{$context}] {$message}";
    if (!empty($data)) {
        $logMessage .= " | Data: " . json_encode($data);
    }

    // Append backtrace if available
    $backtrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 5);
    $traceLines = [];
    foreach ($backtrace as $frame) {
        $file = $frame['file'] ?? '[internal]';
        $line = $frame['line'] ?? 0;
        $func = $frame['function'] ?? '';
        $traceLines[] = "{$file}:{$line} {$func}()";
    }
    if (!empty($traceLines)) {
        $logMessage .= " | Trace: " . implode(' <- ', $traceLines);
    }

    // Write to PHP error log
    error_log($logMessage);

    // Also write to a dedicated debug log for easier inspection
    $debugLog = __DIR__ . '/debug.log';
    @file_put_contents($debugLog, $logMessage . PHP_EOL, FILE_APPEND | LOCK_EX);
}

// Load core classes
require_once BASE_PATH . '/KeyManager.php';
require_once BASE_PATH . '/CryptoEngine.php';

// Check critical requirements
$reqs = checkSystemRequirements();
foreach ($reqs as $name => $req) {
    if ($req['critical'] && !$req['check']) {
        die("CRITICAL ERROR: {$name} is required but not available!");
    }
}
