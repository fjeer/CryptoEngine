<?php
/**
 * CRYPTO ENGINE - Complete Encryption System
 * Version: 2.0 - Production Ready
 */

class CryptoEngine {
    
    // ===========================================
    // ENCODING (Not Encryption)
    // ===========================================
    
    public static function encodeBase64($data) {
        try {
            if (empty($data)) throw new Exception('Data cannot be empty');
            return [
                'encrypted' => base64_encode($data),
                'method' => 'Base64 Encoding'
            ];
        } catch (Exception $e) {
            logError('Base64Encode', $e->getMessage());
            return false;
        }
    }
    
    public static function decodeBase64($encoded) {
        try {
            $decoded = base64_decode($encoded, true);
            if ($decoded === false) throw new Exception('Invalid Base64');
            return $decoded;
        } catch (Exception $e) {
            logError('Base64Decode', $e->getMessage());
            return false;
        }
    }
    
    public static function encodeHex($data) {
        try {
            if (empty($data)) throw new Exception('Data cannot be empty');
            return [
                'encrypted' => bin2hex($data),
                'method' => 'Hexadecimal Encoding'
            ];
        } catch (Exception $e) {
            logError('HexEncode', $e->getMessage());
            return false;
        }
    }
    
    public static function decodeHex($encoded) {
        try {
            $decoded = @hex2bin($encoded);
            if ($decoded === false) throw new Exception('Invalid Hex');
            return $decoded;
        } catch (Exception $e) {
            logError('HexDecode', $e->getMessage());
            return false;
        }
    }
    
    // ===========================================
    // HASHING (One-way)
    // ===========================================
    
    public static function hashSHA256($data) {
        try {
            return [
                'encrypted' => hash('sha256', $data),
                'method' => 'SHA-256 Hash'
            ];
        } catch (Exception $e) {
            logError('SHA256', $e->getMessage());
            return false;
        }
    }
    
    public static function hashSHA512($data) {
        try {
            return [
                'encrypted' => hash('sha512', $data),
                'method' => 'SHA-512 Hash'
            ];
        } catch (Exception $e) {
            logError('SHA512', $e->getMessage());
            return false;
        }
    }
    
    public static function hashSHA3_256($data) {
        try {
            if (!in_array('sha3-256', hash_algos())) {
                throw new Exception('SHA3-256 not supported');
            }
            return [
                'encrypted' => hash('sha3-256', $data),
                'method' => 'SHA3-256 Hash'
            ];
        } catch (Exception $e) {
            logError('SHA3', $e->getMessage());
            return false;
        }
    }
    
    // ===========================================
    // AES-256-GCM (RECOMMENDED)
    // ===========================================
    
    public static function encryptAES256GCM($data, $key) {
        try {
            if (empty($data)) throw new Exception('Data cannot be empty');
            if (empty($key)) throw new Exception('Key cannot be empty');
            
            if (!in_array('aes-256-gcm', openssl_get_cipher_methods())) {
                throw new Exception('AES-256-GCM not supported. Use AES-256-CBC instead.');
            }
            
            $key = hash('sha256', $key, true);
            $nonce = random_bytes(12);
            $tag = '';
            
            $ciphertext = openssl_encrypt(
                $data, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, '', 16
            );
            
            if ($ciphertext === false) {
                throw new Exception('AES-GCM encryption failed: ' . openssl_error_string());
            }
            
            return [
                'encrypted' => base64_encode($nonce . $tag . $ciphertext),
                'method' => 'AES-256-GCM'
            ];
        } catch (Exception $e) {
            logError('AES-GCM-Encrypt', $e->getMessage());
            return false;
        }
    }
    
    public static function decryptAES256GCM($encryptedData, $key) {
        try {
            if (empty($encryptedData)) throw new Exception('Encrypted data cannot be empty');
            if (empty($key)) throw new Exception('Key cannot be empty');
            
            $key = hash('sha256', $key, true);
            $raw = base64_decode($encryptedData);
            
            if ($raw === false || strlen($raw) < 28) {
                throw new Exception('Invalid encrypted data format');
            }
            
            $nonce = substr($raw, 0, 12);
            $tag = substr($raw, 12, 16);
            $ciphertext = substr($raw, 28);
            
            $plaintext = openssl_decrypt(
                $ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag
            );
            
            if ($plaintext === false) {
                throw new Exception('AES-GCM decryption failed: ' . openssl_error_string());
            }
            
            return $plaintext;
        } catch (Exception $e) {
            logError('AES-GCM-Decrypt', $e->getMessage());
            return false;
        }
    }
    
    // ===========================================
    // AES-256-CBC
    // ===========================================
    
    public static function encryptAES256CBC($data, $key) {
        try {
            if (empty($data)) throw new Exception('Data cannot be empty');
            if (empty($key)) throw new Exception('Key cannot be empty');
            
            $key = hash('sha256', $key, true);
            $iv = random_bytes(16);
            
            $ciphertext = openssl_encrypt($data, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
            if ($ciphertext === false) {
                throw new Exception('AES-CBC encryption failed: ' . openssl_error_string());
            }
            
            $hmac = hash_hmac('sha256', $iv . $ciphertext, $key, true);
            
            return [
                'encrypted' => base64_encode($hmac . $iv . $ciphertext),
                'method' => 'AES-256-CBC + HMAC'
            ];
        } catch (Exception $e) {
            logError('AES-CBC-Encrypt', $e->getMessage());
            return false;
        }
    }
    
    public static function decryptAES256CBC($encryptedData, $key) {
        try {
            if (empty($encryptedData)) throw new Exception('Encrypted data cannot be empty');
            if (empty($key)) throw new Exception('Key cannot be empty');
            
            $key = hash('sha256', $key, true);
            $raw = base64_decode($encryptedData);
            
            if ($raw === false || strlen($raw) < 48) {
                throw new Exception('Invalid encrypted data format');
            }
            
            $hmac = substr($raw, 0, 32);
            $iv = substr($raw, 32, 16);
            $ciphertext = substr($raw, 48);
            
            $expectedHmac = hash_hmac('sha256', $iv . $ciphertext, $key, true);
            if (!hash_equals($hmac, $expectedHmac)) {
                throw new Exception('HMAC verification failed');
            }
            
            $plaintext = openssl_decrypt($ciphertext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
            if ($plaintext === false) {
                throw new Exception('AES-CBC decryption failed');
            }
            
            return $plaintext;
        } catch (Exception $e) {
            logError('AES-CBC-Decrypt', $e->getMessage());
            return false;
        }
    }
    
    // ===========================================
    // AES-256-CTR
    // ===========================================
    
    public static function encryptAES256CTR($data, $key) {
        try {
            if (empty($data)) throw new Exception('Data cannot be empty');
            if (empty($key)) throw new Exception('Key cannot be empty');
            
            $key = hash('sha256', $key, true);
            $iv = random_bytes(16);
            
            $ciphertext = openssl_encrypt($data, 'aes-256-ctr', $key, OPENSSL_RAW_DATA, $iv);
            if ($ciphertext === false) {
                throw new Exception('AES-CTR encryption failed');
            }
            
            $hmac = hash_hmac('sha256', $iv . $ciphertext, $key, true);
            
            return [
                'encrypted' => base64_encode($hmac . $iv . $ciphertext),
                'method' => 'AES-256-CTR + HMAC'
            ];
        } catch (Exception $e) {
            logError('AES-CTR-Encrypt', $e->getMessage());
            return false;
        }
    }
    
    public static function decryptAES256CTR($encryptedData, $key) {
        try {
            if (empty($encryptedData)) throw new Exception('Encrypted data cannot be empty');
            if (empty($key)) throw new Exception('Key cannot be empty');
            
            $key = hash('sha256', $key, true);
            $raw = base64_decode($encryptedData);
            
            if ($raw === false || strlen($raw) < 48) {
                throw new Exception('Invalid encrypted data format');
            }
            
            $hmac = substr($raw, 0, 32);
            $iv = substr($raw, 32, 16);
            $ciphertext = substr($raw, 48);
            
            $expectedHmac = hash_hmac('sha256', $iv . $ciphertext, $key, true);
            if (!hash_equals($hmac, $expectedHmac)) {
                throw new Exception('HMAC verification failed');
            }
            
            $plaintext = openssl_decrypt($ciphertext, 'aes-256-ctr', $key, OPENSSL_RAW_DATA, $iv);
            if ($plaintext === false) {
                throw new Exception('AES-CTR decryption failed');
            }
            
            return $plaintext;
        } catch (Exception $e) {
            logError('AES-CTR-Decrypt', $e->getMessage());
            return false;
        }
    }
    
    // ===========================================
    // CAMELLIA-256-CBC
    // ===========================================
    
    public static function encryptCamellia256CBC($data, $key) {
        try {
            if (empty($data)) throw new Exception('Data cannot be empty');
            if (empty($key)) throw new Exception('Key cannot be empty');
            
            if (!in_array('camellia-256-cbc', openssl_get_cipher_methods())) {
                throw new Exception('Camellia-256-CBC not supported on this system');
            }
            
            $key = hash('sha256', $key, true);
            $iv = random_bytes(16);
            
            $ciphertext = openssl_encrypt($data, 'camellia-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
            if ($ciphertext === false) {
                throw new Exception('Camellia encryption failed');
            }
            
            $hmac = hash_hmac('sha256', $iv . $ciphertext, $key, true);
            
            return [
                'encrypted' => base64_encode($hmac . $iv . $ciphertext),
                'method' => 'Camellia-256-CBC + HMAC'
            ];
        } catch (Exception $e) {
            logError('Camellia-Encrypt', $e->getMessage());
            return false;
        }
    }
    
    public static function decryptCamellia256CBC($encryptedData, $key) {
        try {
            if (empty($encryptedData)) throw new Exception('Encrypted data cannot be empty');
            if (empty($key)) throw new Exception('Key cannot be empty');
            
            $key = hash('sha256', $key, true);
            $raw = base64_decode($encryptedData);
            
            if ($raw === false || strlen($raw) < 48) {
                throw new Exception('Invalid encrypted data format');
            }
            
            $hmac = substr($raw, 0, 32);
            $iv = substr($raw, 32, 16);
            $ciphertext = substr($raw, 48);
            
            $expectedHmac = hash_hmac('sha256', $iv . $ciphertext, $key, true);
            if (!hash_equals($hmac, $expectedHmac)) {
                throw new Exception('HMAC verification failed');
            }
            
            $plaintext = openssl_decrypt($ciphertext, 'camellia-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
            if ($plaintext === false) {
                throw new Exception('Camellia decryption failed');
            }
            
            return $plaintext;
        } catch (Exception $e) {
            logError('Camellia-Decrypt', $e->getMessage());
            return false;
        }
    }
    // ===========================================
    // RSA-4096
    // ===========================================
    
    public static function encryptRSA4096($data, $publicKeyPath) {
        try {
            if (empty($data)) throw new Exception('Data cannot be empty');
            if (!file_exists($publicKeyPath)) {
                throw new Exception('Public key not found: ' . basename($publicKeyPath));
            }
            
            $publicKey = openssl_pkey_get_public(file_get_contents($publicKeyPath));
            if (!$publicKey) {
                throw new Exception('Invalid public key: ' . openssl_error_string());
            }
            
            $keyDetails = openssl_pkey_get_details($publicKey);
            $keySize = $keyDetails['bits'];
            $maxSize = ($keySize / 8) - 66;
            
            if (strlen($data) > $maxSize) {
                throw new Exception("Data too large for RSA-{$keySize}. Max: {$maxSize} bytes. Use Hybrid!");
            }
            
            $encrypted = '';
            $result = openssl_public_encrypt($data, $encrypted, $publicKey, OPENSSL_PKCS1_OAEP_PADDING);

            
            if (!$result) {
                throw new Exception('RSA encryption failed: ' . openssl_error_string());
            }
            
            return [
                'encrypted' => base64_encode($encrypted),
                'method' => "RSA-{$keySize}"
            ];
        } catch (Exception $e) {
            logError('RSA-Encrypt', $e->getMessage());
            return false;
        }
    }
    
    public static function decryptRSA4096($encryptedData, $privateKeyPath, $passphrase = '') {
        try {
            if (empty($encryptedData)) throw new Exception('Encrypted data cannot be empty');
            if (!file_exists($privateKeyPath)) {
                throw new Exception('Private key not found: ' . basename($privateKeyPath));
            }
            
            $privateKey = openssl_pkey_get_private(file_get_contents($privateKeyPath), $passphrase);
            if (!$privateKey) {
                throw new Exception('Invalid private key or wrong passphrase: ' . openssl_error_string());
            }
            
            $decrypted = '';
            $result = openssl_private_decrypt(base64_decode($encryptedData), $decrypted, $privateKey, OPENSSL_PKCS1_OAEP_PADDING);
            
            if (!$result) {
                throw new Exception('RSA decryption failed: ' . openssl_error_string());
            }
            
            return $decrypted;
        } catch (Exception $e) {
            logError('RSA-Decrypt', $e->getMessage());
            return false;
        }
    }
    
    // ===========================================
    // HYBRID (AES + RSA)
    // ===========================================
    
    public static function encryptHybrid($data, $publicKeyPath) {
        try {
            if (empty($data)) throw new Exception('Data cannot be empty');
            
            $aesKey = bin2hex(random_bytes(16));
            $aesResult = self::encryptAES256GCM($data, $aesKey);
            if (!$aesResult) throw new Exception('AES encryption failed');
            
            $rsaResult = self::encryptRSA4096($aesKey, $publicKeyPath);
            if (!$rsaResult) throw new Exception('RSA key encryption failed');
            
            return [
                'encrypted' => $aesResult['encrypted'],
                'encrypted_key' => $rsaResult['encrypted'],
                'method' => 'Hybrid (AES-256-GCM + RSA)'
            ];
        } catch (Exception $e) {
            logError('Hybrid-Encrypt', $e->getMessage());
            return false;
        }
    }
    
    public static function decryptHybrid($encryptedData, $encryptedKey, $privateKeyPath, $passphrase = '') {
        try {
            if (empty($encryptedData)) throw new Exception('Encrypted data cannot be empty');
            if (empty($encryptedKey)) throw new Exception('Encrypted key cannot be empty');
            
            $aesKey = self::decryptRSA4096($encryptedKey, $privateKeyPath, $passphrase);
            if ($aesKey === false) throw new Exception('Failed to decrypt AES key');
            
            $plaintext = self::decryptAES256GCM($encryptedData, $aesKey);
            if ($plaintext === false) throw new Exception('Failed to decrypt data');
            
            return $plaintext;
        } catch (Exception $e) {
            logError('Hybrid-Decrypt', $e->getMessage());
            return false;
        }
    }
    
    // ===========================================
    // FULL-CHAIN (Hash + AES + RSA)
    // ===========================================
    
    public static function encryptFullChain($data, $publicKeyPath) {
        try {
            if (empty($data)) throw new Exception('Data cannot be empty');
            
            $hash = hash('sha256', $data, true);
            $dataWithHash = $hash . $data;
            
            $result = self::encryptHybrid($dataWithHash, $publicKeyPath);
            if (!$result) throw new Exception('Hybrid encryption failed');
            
            $result['method'] = 'Full-Chain (SHA-256 + AES-256-GCM + RSA)';
            return $result;
        } catch (Exception $e) {
            logError('FullChain-Encrypt', $e->getMessage());
            return false;
        }
    }
    
    public static function decryptFullChain($encryptedData, $encryptedKey, $privateKeyPath, $passphrase = '') {
        try {
            $dataWithHash = self::decryptHybrid($encryptedData, $encryptedKey, $privateKeyPath, $passphrase);
            if ($dataWithHash === false) throw new Exception('Hybrid decryption failed');
            
            if (strlen($dataWithHash) < 32) throw new Exception('Invalid full-chain format');
            
            $storedHash = substr($dataWithHash, 0, 32);
            $originalData = substr($dataWithHash, 32);
            $calculatedHash = hash('sha256', $originalData, true);
            
            if (!hash_equals($storedHash, $calculatedHash)) {
                throw new Exception('Data integrity check failed - data tampered!');
            }
            
            return $originalData;
        } catch (Exception $e) {
            logError('FullChain-Decrypt', $e->getMessage());
            return false;
        }
    }
    
    // ===========================================
    // TRIPLE-LAYER (AES + Camellia + RSA)
    // ===========================================
    
    public static function encryptTripleLayer($data, $secretKey, $publicKeyPath) {
        try {
            if (empty($data)) throw new Exception('Data cannot be empty');
            if (empty($secretKey)) throw new Exception('Secret key cannot be empty');
            
            $layer1 = self::encryptAES256CBC($data, $secretKey);
            if (!$layer1) throw new Exception('Layer 1 (AES-CBC) failed');
            
            $layer2 = self::encryptCamellia256CBC($layer1['encrypted'], $secretKey);
            if (!$layer2) throw new Exception('Layer 2 (Camellia) failed');
            
            $rsaResult = self::encryptRSA4096($secretKey, $publicKeyPath);
            if (!$rsaResult) throw new Exception('Layer 3 (RSA) failed');
            
            return [
                'encrypted' => $layer2['encrypted'],
                'encrypted_key' => $rsaResult['encrypted'],
                'method' => 'Triple-Layer (AES-CBC + Camellia + RSA)'
            ];
        } catch (Exception $e) {
            logError('TripleLayer-Encrypt', $e->getMessage());
            return false;
        }
    }
    
    public static function decryptTripleLayer($encryptedData, $encryptedKey, $privateKeyPath, $passphrase = '') {
        try {
            if (empty($encryptedData)) throw new Exception('Encrypted data cannot be empty');
            if (empty($encryptedKey)) throw new Exception('Encrypted key cannot be empty');
            
            $secretKey = self::decryptRSA4096($encryptedKey, $privateKeyPath, $passphrase);
            if ($secretKey === false) throw new Exception('Key decryption failed');
            
            $layer2 = self::decryptCamellia256CBC($encryptedData, $secretKey);
            if ($layer2 === false) throw new Exception('Layer 2 decryption failed');
            
            $plaintext = self::decryptAES256CBC($layer2, $secretKey);
            if ($plaintext === false) throw new Exception('Layer 1 decryption failed');
            
            return $plaintext;
        } catch (Exception $e) {
            logError('TripleLayer-Decrypt', $e->getMessage());
            return false;
        }
    }
    
    // ===========================================
    // FILE ENCRYPTION WRAPPERS
    // ===========================================
    
    public static function encryptFile($filePath, $method, $key = '', $publicKeyPath = '') {
        try {
            if (!file_exists($filePath)) throw new Exception('File not found');
            
            $content = file_get_contents($filePath);
            if ($content === false) throw new Exception('Cannot read file');
            
            logError('FileEncrypt', "Method={$method}, Size=" . strlen($content));
            
            switch ($method) {
                case 'base64':
                    return self::encodeBase64($content);
                case 'hex':
                    return self::encodeHex($content);
                case 'aes-cbc':
                    if (empty($key)) throw new Exception('Secret key required for AES-CBC');
                    return self::encryptAES256CBC($content, $key);
                case 'aes':
                case 'aes-gcm':
                    if (empty($key)) throw new Exception('Secret key required for AES-GCM');
                    return self::encryptAES256GCM($content, $key);
                case 'aes-ctr':
                    if (empty($key)) throw new Exception('Secret key required for AES-CTR');
                    return self::encryptAES256CTR($content, $key);
                case 'camellia':
                    if (empty($key)) throw new Exception('Secret key required for Camellia');
                    return self::encryptCamellia256CBC($content, $key);
                case 'rsa':
                    if (strlen($content) > 446) {
                        throw new Exception('File too large for RSA. Use Hybrid!');
                    }
                    return self::encryptRSA4096($content, $publicKeyPath);
                case 'hybrid':
                    return self::encryptHybrid($content, $publicKeyPath);
                case 'fullchain':
                    return self::encryptFullChain($content, $publicKeyPath);
                case 'triplelayer':
                    if (empty($key)) throw new Exception('Secret key required for Triple-Layer');
                    return self::encryptTripleLayer($content, $key, $publicKeyPath);
                default:
                    throw new Exception('Unknown method: ' . $method);
            }
        } catch (Exception $e) {
            logError('FileEncrypt-Error', $e->getMessage(), ['method' => $method]);
            return false;
        }
    }
    
    public static function decryptFile($encryptedData, $method, $key = '', $privateKeyPath = '', $passphrase = '', $encryptedKey = '') {
        try {
            if (empty($encryptedData)) throw new Exception('Encrypted data cannot be empty');
            
            logError('FileDecrypt', "Method={$method}");
            
            switch ($method) {
                case 'base64':
                    return self::decodeBase64($encryptedData);
                case 'hex':
                    return self::decodeHex($encryptedData);
                case 'aes-cbc':
                    if (empty($key)) throw new Exception('Secret key required for AES-CBC');
                    return self::decryptAES256CBC($encryptedData, $key);
                case 'aes':
                case 'aes-gcm':
                    if (empty($key)) throw new Exception('Secret key required for AES-GCM');
                    return self::decryptAES256GCM($encryptedData, $key);
                case 'aes-ctr':
                    if (empty($key)) throw new Exception('Secret key required for AES-CTR');
                    return self::decryptAES256CTR($encryptedData, $key);
                case 'camellia':
                    if (empty($key)) throw new Exception('Secret key required for Camellia');
                    return self::decryptCamellia256CBC($encryptedData, $key);
                case 'rsa':
                    return self::decryptRSA4096($encryptedData, $privateKeyPath, $passphrase);
                case 'hybrid':
                    if (empty($encryptedKey)) throw new Exception('Encrypted key required for Hybrid');
                    return self::decryptHybrid($encryptedData, $encryptedKey, $privateKeyPath, $passphrase);
                case 'fullchain':
                    if (empty($encryptedKey)) throw new Exception('Encrypted key required for Full-Chain');
                    return self::decryptFullChain($encryptedData, $encryptedKey, $privateKeyPath, $passphrase);
                case 'triplelayer':
                    if (empty($encryptedKey)) throw new Exception('Encrypted key required for Triple-Layer');
                    return self::decryptTripleLayer($encryptedData, $encryptedKey, $privateKeyPath, $passphrase);
                default:
                    throw new Exception('Unknown method: ' . $method);
            }
        } catch (Exception $e) {
            logError('FileDecrypt-Error', $e->getMessage(), ['method' => $method]);
            return false;
        }
    }
}
?>
