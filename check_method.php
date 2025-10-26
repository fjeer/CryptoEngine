<?php
/**
 * CHECK METHOD - Auto-detect encryption method from .enc file
 */

require_once 'config.php';
header('Content-Type: application/json; charset=utf-8');
// Start output buffering to capture any unexpected output (helps debugging non-JSON responses)
if (!ob_get_level()) ob_start();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'error' => 'Invalid request method']);
    exit;
}

try {
    if (!isset($_FILES['encrypted_file']) || $_FILES['encrypted_file']['error'] !== UPLOAD_ERR_OK) {
        throw new Exception('File upload failed');
    }
    
    $tmpPath = $_FILES['encrypted_file']['tmp_name'];
    $fileContent = file_get_contents($tmpPath);
    $encryptedData = json_decode($fileContent, true);
    
    if (!$encryptedData || !isset($encryptedData['encrypted_data'])) {
        throw new Exception('Invalid encrypted file format');
    }
    
    $actualMethod = $encryptedData['actual_method'] ?? $encryptedData['method'] ?? 'unknown';
    
    // Backward compatibility
    if (!isset($encryptedData['actual_method']) && isset($encryptedData['method'])) {
        $methodName = strtolower($encryptedData['method']);
        if (strpos($methodName, 'hybrid') !== false) {
            $actualMethod = 'hybrid';
        } elseif (strpos($methodName, 'full-chain') !== false) {
            $actualMethod = 'fullchain';
        } elseif (strpos($methodName, 'triple') !== false) {
            $actualMethod = 'triplelayer';
        } elseif (strpos($methodName, 'aes-256-gcm') !== false) {
            $actualMethod = 'aes-gcm';
        } elseif (strpos($methodName, 'aes-256-cbc') !== false) {
            $actualMethod = 'aes-cbc';
        } elseif (strpos($methodName, 'aes-256-ctr') !== false) {
            $actualMethod = 'aes-ctr';
        } elseif (strpos($methodName, 'camellia') !== false) {
            $actualMethod = 'camellia';
        } elseif (strpos($methodName, 'rsa') !== false) {
            $actualMethod = 'rsa';
        }
    }
    
    $needsSecretKey = in_array($actualMethod, ['aes-cbc', 'aes-gcm', 'aes-ctr', 'camellia', 'triplelayer']);
    $needsPrivateKey = in_array($actualMethod, ['rsa', 'hybrid', 'fullchain', 'triplelayer']);
    $hasEncryptedKey = isset($encryptedData['encrypted_key']) && !empty($encryptedData['encrypted_key']);
    
    echo json_encode([
        'success' => true,
        'method' => $actualMethod,
        'method_display' => $encryptedData['method'] ?? 'Unknown',
        'original_name' => $encryptedData['original_name'] ?? 'unknown',
        'file_size' => $encryptedData['file_size'] ?? 0,
        'mime_type' => $encryptedData['mime_type'] ?? 'unknown',
        'encrypted_at' => $encryptedData['encrypted_at'] ?? 'unknown',
        'needs_secret_key' => $needsSecretKey,
        'needs_private_key' => $needsPrivateKey,
        'has_encrypted_key' => $hasEncryptedKey
    ]);
    
} catch (Exception $e) {
    http_response_code(400);
    // Capture any stray output
    $strayOutput = '';
    if (ob_get_level()) {
        $strayOutput = trim(ob_get_clean());
    }

    $response = ['success' => false, 'error' => $e->getMessage()];
    if (!empty($strayOutput)) $response['output'] = $strayOutput;

    echo json_encode($response);
}
?>
