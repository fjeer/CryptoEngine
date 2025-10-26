<?php
/**
 * PROCESS.PHP - Main API Endpoint
 * Handles all encryption/decryption requests
 */

require_once 'config.php';
header('Content-Type: application/json; charset=utf-8');

ini_set('display_errors', 1);
error_reporting(E_ALL);
// Start output buffering to capture any unexpected output (helps debugging non-JSON responses)
if (!ob_get_level()) ob_start();

// Temporary debug: capture fatal errors and convert to JSON response
register_shutdown_function(function () {
    $err = error_get_last();
    if ($err && in_array($err['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR])) {
        $output = '';
        if (ob_get_level()) {
            $output = trim(ob_get_clean());
        }

        $msg = "Fatal: {$err['message']} in {$err['file']} on line {$err['line']}";
        logError('ShutdownError', $msg, ['output' => $output]);

        http_response_code(500);
        $response = ['success' => false, 'error' => $msg];
        if (!empty($output)) $response['output'] = $output;
        echo json_encode($response);
        exit;
    }
});

set_error_handler(function ($severity, $message, $file, $line) {
    // Convert warnings/notices into logged entries and include in output buffer
    $msg = "PHP Error: {$message} in {$file} on line {$line}";
    logError('PhpError', $msg);
    return false; // allow normal handling as well
});

try {
    $action = $_POST['action'] ?? '';
    
    if (empty($action)) {
        throw new Exception('Action parameter required');
    }
    
    logError('Process', "Action: {$action}");
    
    // ==========================================
    // ENCRYPT TEXT
    // ==========================================
    if ($action === 'encrypt_text') {
        $plaintext = $_POST['plaintext'] ?? '';
        $method = $_POST['method'] ?? '';
        $secretKey = $_POST['secret_key'] ?? '';
        $publicKeyName = $_POST['public_key'] ?? '';
        
        if (empty($plaintext)) throw new Exception('Plaintext cannot be empty');
        if (empty($method)) throw new Exception('Method must be selected');
        
        $needsRSA = in_array($method, ['rsa', 'hybrid', 'fullchain', 'triplelayer']);
        $needsKey = in_array($method, ['aes-cbc', 'aes-gcm', 'aes', 'aes-ctr', 'camellia', 'triplelayer']);
        
        if ($needsRSA) {
            if (empty($publicKeyName)) throw new Exception('Public key required for ' . strtoupper($method));
            $publicKeyPath = KEYS_DIR . '/' . $publicKeyName . '_public.pem';
            if (!file_exists($publicKeyPath)) throw new Exception('Public key not found');
        }
        
        if ($needsKey && empty($secretKey)) {
            throw new Exception('Secret key required for ' . strtoupper($method));
        }
        
        $result = null;
        $startTime = microtime(true);

        switch ($method) {
            case 'base64':
                $result = CryptoEngine::encodeBase64($plaintext);
                break;
            case 'hex':
                $result = CryptoEngine::encodeHex($plaintext);
                break;
            case 'sha256':
                $result = CryptoEngine::hashSHA256($plaintext);
                break;
            case 'sha512':
                $result = CryptoEngine::hashSHA512($plaintext);
                break;
            case 'sha3-256':
                $result = CryptoEngine::hashSHA3_256($plaintext);
                break;
            case 'aes-cbc':
                $result = CryptoEngine::encryptAES256CBC($plaintext, $secretKey);
                break;
            case 'aes':
            case 'aes-gcm':
                $result = CryptoEngine::encryptAES256GCM($plaintext, $secretKey);
                break;
            case 'aes-ctr':
                $result = CryptoEngine::encryptAES256CTR($plaintext, $secretKey);
                break;
            case 'camellia':
                $result = CryptoEngine::encryptCamellia256CBC($plaintext, $secretKey);
                break;
            case 'rsa':
                $result = CryptoEngine::encryptRSA4096($plaintext, $publicKeyPath);
                break;
            case 'hybrid':
                $result = CryptoEngine::encryptHybrid($plaintext, $publicKeyPath);
                break;
            case 'fullchain':
                $result = CryptoEngine::encryptFullChain($plaintext, $publicKeyPath);
                break;
            case 'triplelayer':
                $result = CryptoEngine::encryptTripleLayer($plaintext, $secretKey, $publicKeyPath);
                break;
            default:
                throw new Exception('Unknown method: ' . $method);
        }

        $endTime = microtime(true);
        $timeTaken = $endTime - $startTime;

        if (!$result) throw new Exception('Encryption failed. Check error.log');

        $originalSize = strlen($plaintext);
        $encryptedData = is_array($result) ? $result['encrypted'] : $result;
        $encryptedSize = strlen($encryptedData);
        
        echo json_encode([
            'success' => true,
            'encrypted' => $result['encrypted'],
            'encrypted_key' => $result['encrypted_key'] ?? null,
            'method' => $result['method'],
            'actual_method' => $method,
            'time_taken' => number_format($timeTaken, 6),
            'original_size' => $originalSize,          
            'encrypted_size' => $encryptedSize 
        ]);
        exit;
    }
    
    // ==========================================
    // DECRYPT TEXT
    // ==========================================
    elseif ($action === 'decrypt_text') {
        $encryptedText = $_POST['encrypted_text'] ?? '';
        $method = $_POST['method'] ?? '';
        $secretKey = $_POST['secret_key'] ?? '';
        $privateKeyName = $_POST['private_key'] ?? '';
        $passphrase = $_POST['passphrase'] ?? '';
        $encryptedKey = $_POST['encrypted_key'] ?? '';
        
        if (empty($encryptedText)) throw new Exception('Encrypted text cannot be empty');
        if (empty($method)) throw new Exception('Method must be selected');
        
        $needsRSA = in_array($method, ['rsa', 'hybrid', 'fullchain', 'triplelayer']);
        
        if ($needsRSA) {
            if (empty($privateKeyName)) throw new Exception('Private key required');
            $privateKeyPath = KEYS_DIR . '/' . $privateKeyName . '_private.pem';
            if (!file_exists($privateKeyPath)) throw new Exception('Private key not found');
        }
        
        $plaintext = null;
        
        switch ($method) {
            case 'base64':
                $plaintext = CryptoEngine::decodeBase64($encryptedText);
                break;
            case 'hex':
                $plaintext = CryptoEngine::decodeHex($encryptedText);
                break;
            case 'sha256':
            case 'sha512':
            case 'sha3-256':
                throw new Exception('Hash functions are one-way and cannot be decrypted');
            case 'aes-cbc':
                $plaintext = CryptoEngine::decryptAES256CBC($encryptedText, $secretKey);
                break;
            case 'aes':
            case 'aes-gcm':
                $plaintext = CryptoEngine::decryptAES256GCM($encryptedText, $secretKey);
                break;
            case 'aes-ctr':
                $plaintext = CryptoEngine::decryptAES256CTR($encryptedText, $secretKey);
                break;
            case 'camellia':
                $plaintext = CryptoEngine::decryptCamellia256CBC($encryptedText, $secretKey);
                break;
            case 'rsa':
                $plaintext = CryptoEngine::decryptRSA4096($encryptedText, $privateKeyPath, $passphrase);
                break;
            case 'hybrid':
                if (empty($encryptedKey)) throw new Exception('Encrypted key required for Hybrid');
                $plaintext = CryptoEngine::decryptHybrid($encryptedText, $encryptedKey, $privateKeyPath, $passphrase);
                break;
            case 'fullchain':
                if (empty($encryptedKey)) throw new Exception('Encrypted key required for Full-Chain');
                $plaintext = CryptoEngine::decryptFullChain($encryptedText, $encryptedKey, $privateKeyPath, $passphrase);
                break;
            case 'triplelayer':
                if (empty($encryptedKey)) throw new Exception('Encrypted key required for Triple-Layer');
                $plaintext = CryptoEngine::decryptTripleLayer($encryptedText, $encryptedKey, $privateKeyPath, $passphrase);
                break;
            default:
                throw new Exception('Unknown method: ' . $method);
        }
        
        if ($plaintext === false) throw new Exception('Decryption failed. Check keys and data.');
        
        echo json_encode([
            'success' => true,
            'decrypted' => $plaintext
        ]);
        exit;
    }
    
    // ==========================================
    // ENCRYPT FILE
    // ==========================================
    elseif ($action === 'encrypt_file') {
        if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
            throw new Exception('File upload failed (Error: ' . ($_FILES['file']['error'] ?? 'unknown') . ')');
        }
        
        $method = $_POST['method'] ?? '';
        $secretKey = $_POST['secret_key'] ?? '';
        $publicKeyName = $_POST['public_key'] ?? '';
        
        $file = $_FILES['file'];
        $originalName = basename($file['name']);
        $tmpPath = $file['tmp_name'];
        $fileSize = $file['size'];
        
        if ($fileSize > MAX_FILE_SIZE) {
            throw new Exception('File too large. Max: ' . formatFileSize(MAX_FILE_SIZE));
        }
        if ($fileSize === 0) throw new Exception('Cannot encrypt empty file');
        
        $needsRSA = in_array($method, ['rsa', 'hybrid', 'fullchain', 'triplelayer']);
        
        if ($needsRSA) {
            if (empty($publicKeyName)) throw new Exception('Public key required');
            $publicKeyPath = KEYS_DIR . '/' . $publicKeyName . '_public.pem';
            if (!file_exists($publicKeyPath)) throw new Exception('Public key not found');
        }
        $startEncrypt_file = microtime(true);
        $result = CryptoEngine::encryptFile($tmpPath, $method, $secretKey, $publicKeyPath ?? '');
        $endEncrypt_file = microtime(true);
        $timeEncrypt_file = $endEncrypt_file - $startEncrypt_file;
        $encryptedSize = strlen($result['encrypted']) / 1024;
        
        if (!$result) throw new Exception('File encryption failed. Check error.log');
        
        $encryptedFileName = pathinfo($originalName, PATHINFO_FILENAME) . '_' . time() . '.enc';
        $encryptedFilePath = ENCRYPTED_DIR . '/' . $encryptedFileName;
        
        $encryptedData = [
            'original_name' => $originalName,
            'encrypted_data' => $result['encrypted'],
            'encrypted_key' => $result['encrypted_key'] ?? null,
            'method' => $result['method'],
            'actual_method' => $method,
            'file_size' => $fileSize,
            'encrypted_size_kb' => number_format($encryptedSize, 2),
            'encryption_time_sec' => number_format($timeEncrypt_file, 6),
            'mime_type' => getMimeType($tmpPath),
            'encrypted_at' => date('Y-m-d H:i:s')
        ];
        
        $saved = file_put_contents($encryptedFilePath, json_encode($encryptedData, JSON_PRETTY_PRINT));
        if ($saved === false) throw new Exception('Failed to save encrypted file');
        
        echo json_encode([
            'success' => true,
            'encrypted_file' => $encryptedFileName,
            'original_name' => $originalName,
            'method' => $result['method'],
            'download_url' => 'download.php?dir=encrypted&file=' . urlencode($encryptedFileName),
            'encryption_time_sec' => number_format($timeEncrypt_file, 6), 
            'encrypted_size_kb' => number_format($encryptedSize, 2),      
            'original_size_kb' => number_format($fileSize / 1024, 2) 
            ]);
        exit;
    }
    
    // ==========================================
    // DECRYPT FILE
    // ==========================================
    elseif ($action === 'decrypt_file') {
        if (!isset($_FILES['encrypted_file']) || $_FILES['encrypted_file']['error'] !== UPLOAD_ERR_OK) {
            throw new Exception('Encrypted file upload failed');
        }
        
        $method = $_POST['method'] ?? '';
        $secretKey = $_POST['secret_key'] ?? '';
        $privateKeyName = $_POST['private_key'] ?? '';
        $passphrase = $_POST['passphrase'] ?? '';
        
        $tmpPath = $_FILES['encrypted_file']['tmp_name'];
        $fileContent = file_get_contents($tmpPath);
        
        if ($fileContent === false) throw new Exception('Cannot read encrypted file');
        
        $encryptedData = json_decode($fileContent, true);
        
        if (!$encryptedData || !isset($encryptedData['encrypted_data'])) {
            throw new Exception('Invalid encrypted file format');
        }
        
        if (empty($method)) {
            $method = $encryptedData['actual_method'] ?? '';
        }
        if (empty($method)) throw new Exception('Cannot determine decryption method');
        
        $needsRSA = in_array($method, ['rsa', 'hybrid', 'fullchain', 'triplelayer']);
        
        if ($needsRSA) {
            if (empty($privateKeyName)) throw new Exception('Private key required');
            $privateKeyPath = KEYS_DIR . '/' . $privateKeyName . '_private.pem';
            if (!file_exists($privateKeyPath)) throw new Exception('Private key not found');
        }
        
        $decrypted = CryptoEngine::decryptFile(
            $encryptedData['encrypted_data'],
            $method,
            $secretKey,
            $privateKeyPath ?? '',
            $passphrase,
            $encryptedData['encrypted_key'] ?? ''
        );
        
        if ($decrypted === false) throw new Exception('Decryption failed. Check keys and method.');
        
        $originalName = $encryptedData['original_name'] ?? 'decrypted_file';
        $ext = getFileExtension($originalName);
        $decryptedFileName = pathinfo($originalName, PATHINFO_FILENAME) . '_decrypted_' . time() . '.' . $ext;
        $decryptedFilePath = DECRYPTED_DIR . '/' . $decryptedFileName;
        
        $saved = file_put_contents($decryptedFilePath, $decrypted);
        if ($saved === false) throw new Exception('Failed to save decrypted file');
        
        $previewInfo = canPreviewFile($originalName);
        $previewUrl = null;
        
        if ($previewInfo['can_preview']) {
            $previewFileName = $decryptedFileName;
            $previewFilePath = PREVIEW_DIR . '/' . $previewFileName;
            copy($decryptedFilePath, $previewFilePath);
            $previewUrl = 'preview.php?file=' . urlencode($previewFileName);
        }
        
        echo json_encode([
            'success' => true,
            'decrypted_file' => $decryptedFileName,
            'original_name' => $originalName,
            'file_size' => strlen($decrypted),
            'mime_type' => $encryptedData['mime_type'] ?? getMimeType($decryptedFilePath),
            'can_preview' => $previewInfo['can_preview'],
            'preview_type' => $previewInfo['type'],
            'preview_url' => $previewUrl,
            'download_url' => 'download.php?dir=decrypted&file=' . urlencode($decryptedFileName)
        ]);
        exit;
    }
    
    else {
        throw new Exception('Invalid action: ' . $action);
    }
    
} catch (Exception $e) {
    http_response_code(400);
    // Capture any stray output that may have been echoed before the exception
    $strayOutput = '';
    if (ob_get_level()) {
        $strayOutput = trim(ob_get_clean());
    }

    $extra = ['action' => $_POST['action'] ?? 'unknown', 'output' => $strayOutput];
    // If TEST_DEBUG is set, add request and files metadata (no file contents)
    if (!empty(getenv('TEST_DEBUG'))) {
        $extra['POST'] = array_keys($_POST);
        $extra['FILES'] = array_map(function($f){ return ['name'=>$f['name'] ?? null, 'size'=>$f['size'] ?? null, 'error'=>$f['error'] ?? null]; }, $_FILES);
        $extra['HEADERS'] = getallheaders();
    }
    logError('ProcessError', $e->getMessage(), $extra);
    $response = [
        'success' => false,
        'error' => $e->getMessage()
    ];
    if (!empty($strayOutput)) {
        // Include the stray output to help diagnose non-JSON or fatal errors
        $response['output'] = $strayOutput;
    }

    echo json_encode($response);
    exit;
}
?>
