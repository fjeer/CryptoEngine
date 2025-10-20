<?php
// CryptoEngine.php
class CryptoEngine
{
    /* -------------------------
     * Basic Encoders & Hashes
     * ------------------------- */
    public static function encodeBase64(string $data): string
    {
        return base64_encode($data);
    }
    public static function decodeBase64(string $data): string
    {
        return base64_decode($data);
    }
    public static function encodeHex(string $data): string
    {
        return bin2hex($data);
    }
    public static function decodeHex(string $data): string
    {
        return hex2bin($data);
    }
    public static function hashSHA256(string $data): string
    {
        return hash('sha256', $data);
    }
    public static function hashSHA512(string $data): string
    {
        return hash('sha512', $data);
    }
    public static function hashSHA3_256(string $data): string
    {
        return hash('sha3-256', $data);
    }

    /* -------------------------
     * AES (CBC, GCM, CTR) - encrypt/decrypt
     * ------------------------- */
    public static function encryptAES256CBC(string $plaintext, string $key): string
    {
        $k = substr(hash('sha256', $key, true), 0, 32);
        $iv = random_bytes(16);
        $ct = openssl_encrypt($plaintext, 'AES-256-CBC', $k, OPENSSL_RAW_DATA, $iv);
        return base64_encode($iv . $ct);
    }

    public static function decryptAES256CBC(string $ciphertext, string $key): string
    {
        $data = base64_decode($ciphertext);
        if ($data === false || strlen($data) < 16)
            return '';
        $iv = substr($data, 0, 16);
        $raw = substr($data, 16);
        $k = substr(hash('sha256', $key, true), 0, 32);
        return openssl_decrypt($raw, 'AES-256-CBC', $k, OPENSSL_RAW_DATA, $iv);
    }

    public static function encryptAES256GCM(string $plaintext, string $key): string
    {
        $k = substr(hash('sha256', $key, true), 0, 32);
        $iv = random_bytes(12);
        $tag = '';
        $ct = openssl_encrypt($plaintext, 'aes-256-gcm', $k, OPENSSL_RAW_DATA, $iv, $tag);
        return base64_encode($iv . $tag . $ct);
    }

    public static function decryptAES256GCM(string $ciphertext, string $key): string
    {
        $data = base64_decode($ciphertext);
        if ($data === false || strlen($data) < (12 + 16))
            return '';
        $iv = substr($data, 0, 12);
        $tag = substr($data, 12, 16);
        $raw = substr($data, 28);
        $k = substr(hash('sha256', $key, true), 0, 32);
        return openssl_decrypt($raw, 'aes-256-gcm', $k, OPENSSL_RAW_DATA, $iv, $tag);
    }

    public static function encryptAES256CTR(string $plaintext, string $key): string
    {
        $k = substr(hash('sha256', $key, true), 0, 32);
        $iv = random_bytes(16);
        $ct = openssl_encrypt($plaintext, 'aes-256-ctr', $k, OPENSSL_RAW_DATA, $iv);
        return base64_encode($iv . $ct);
    }

    public static function decryptAES256CTR(string $ciphertext, string $key): string
    {
        $data = base64_decode($ciphertext);
        if ($data === false || strlen($data) < 16)
            return '';
        $iv = substr($data, 0, 16);
        $raw = substr($data, 16);
        $k = substr(hash('sha256', $key, true), 0, 32);
        return openssl_decrypt($raw, 'aes-256-ctr', $k, OPENSSL_RAW_DATA, $iv);
    }

    /* -------------------------
     * Camellia 256-CBC
     * ------------------------- */
    public static function encryptCamellia256CBC(string $plaintext, string $key): string
    {
        $k = substr(hash('sha256', $key, true), 0, 32);
        $iv = random_bytes(16);
        $ct = openssl_encrypt($plaintext, 'CAMELLIA-256-CBC', $k, OPENSSL_RAW_DATA, $iv);
        return base64_encode($iv . $ct);
    }

    public static function decryptCamellia256CBC(string $ciphertext, string $key): string
    {
        $data = base64_decode($ciphertext);
        if ($data === false || strlen($data) < 16)
            return '';
        $iv = substr($data, 0, 16);
        $raw = substr($data, 16);
        $k = substr(hash('sha256', $key, true), 0, 32);
        return openssl_decrypt($raw, 'CAMELLIA-256-CBC', $k, OPENSSL_RAW_DATA, $iv);
    }

    /* -------------------------
     * RSA 4096
     * ------------------------- */
    public static function encryptRSA4096(string $plaintext, string $publicKeyPath): string
    {
        $publicKey = @file_get_contents($publicKeyPath);
        if (!$publicKey)
            throw new Exception("Public key not found: $publicKeyPath");
        $pub = openssl_pkey_get_public($publicKey);
        if (!$pub)
            throw new Exception("Invalid public key: $publicKeyPath");
        $ok = openssl_public_encrypt($plaintext, $encrypted, $pub, OPENSSL_PKCS1_OAEP_PADDING);
        if (!$ok)
            throw new Exception("RSA encryption failed");
        return base64_encode($encrypted);
    }

    public static function decryptRSA4096(string $ciphertext, string $privateKeyPath, string $passphrase = ''): string
    {
        $private = @file_get_contents($privateKeyPath);
        if (!$private)
            throw new Exception("Private key not found: $privateKeyPath");
        $priv = openssl_pkey_get_private($private, $passphrase);
        if (!$priv)
            throw new Exception("Invalid private key: $privateKeyPath");
        $ok = openssl_private_decrypt(base64_decode($ciphertext), $decrypted, $priv, OPENSSL_PKCS1_OAEP_PADDING);
        if (!$ok)
            throw new Exception("RSA decryption failed");
        return $decrypted;
    }

    /* -------------------------
     * Hybrid (AES + RSA)
     * ------------------------- */
    public static function encryptHybrid(string $plaintext, string $publicKeyPath): string
    {
        $aesKey = random_bytes(32);
        $iv = random_bytes(16);
        $data = openssl_encrypt($plaintext, 'AES-256-CBC', $aesKey, OPENSSL_RAW_DATA, $iv);
        $publicKey = @file_get_contents($publicKeyPath);
        if (!$publicKey)
            throw new Exception("Public key not found: $publicKeyPath");
        openssl_public_encrypt($aesKey, $encryptedKey, $publicKey, OPENSSL_PKCS1_OAEP_PADDING);
        $payload = json_encode([
            'key' => base64_encode($encryptedKey),
            'iv' => base64_encode($iv),
            'data' => base64_encode($data)
        ]);
        return base64_encode($payload);
    }

    public static function decryptHybrid(string $ciphertext, string $privateKeyPath, string $passphrase = ''): string
    {
        $decoded = json_decode(base64_decode($ciphertext), true);
        if (!$decoded)
            throw new Exception("Invalid hybrid payload");
        $encryptedKey = base64_decode($decoded['key']);
        $iv = base64_decode($decoded['iv']);
        $data = base64_decode($decoded['data']);
        $private = @file_get_contents($privateKeyPath);
        if (!$private)
            throw new Exception("Private key not found: $privateKeyPath");
        openssl_private_decrypt($encryptedKey, $aesKey, $private, OPENSSL_PKCS1_OAEP_PADDING);
        return openssl_decrypt($data, 'AES-256-CBC', $aesKey, OPENSSL_RAW_DATA, $iv);
    }

    /* -------------------------
     * FullChain & TripleLayer
     * ------------------------- */
    public static function encryptFullChain(string $plaintext, string $publicKeyPath): string
    {
        $step1 = self::encryptAES256CBC($plaintext, 'default_chain_key');
        $step2 = self::encryptRSA4096($step1, $publicKeyPath);
        return base64_encode($step2);
    }

    public static function decryptFullChain(string $ciphertext, string $privateKeyPath, string $passphrase = ''): string
    {
        $rsa_decrypted = self::decryptRSA4096(self::decodeBase64($ciphertext), $privateKeyPath, $passphrase);
        return self::decryptAES256CBC($rsa_decrypted, 'default_chain_key');
    }

    public static function encryptTripleLayer(string $plaintext, string $secretKey, string $publicKeyPath): string
    {
        $a = self::encryptAES256CBC($plaintext, $secretKey);
        $b = self::encryptCamellia256CBC($a, $secretKey);
        $c = self::encryptRSA4096($b, $publicKeyPath);
        return $c;
    }

    public static function decryptTripleLayer(string $ciphertext, string $secretKey, string $privateKeyPath, string $passphrase = ''): string
    {
        $rsa = self::decryptRSA4096($ciphertext, $privateKeyPath, $passphrase);
        $cam = self::decryptCamellia256CBC($rsa, $secretKey);
        return self::decryptAES256CBC($cam, $secretKey);
    }

    /* -------------------------
     * Helpers to encrypt/decrypt data or files given method
     * ------------------------- */
    public static function encryptByMethod(string $method, string $plaintext, string $secretKey = '', string $publicKeyPath = ''): string
    {
        switch ($method) {
            case 'base64':
                return self::encodeBase64($plaintext);
            case 'hex':
                return self::encodeHex($plaintext);
            case 'sha256':
                return self::hashSHA256($plaintext);
            case 'sha512':
                return self::hashSHA512($plaintext);
            case 'sha3-256':
                return self::hashSHA3_256($plaintext);
            case 'aes-cbc':
                return self::encryptAES256CBC($plaintext, $secretKey);
            case 'aes-gcm':
                return self::encryptAES256GCM($plaintext, $secretKey);
            case 'aes-ctr':
                return self::encryptAES256CTR($plaintext, $secretKey);
            case 'camellia':
                return self::encryptCamellia256CBC($plaintext, $secretKey);
            case 'rsa':
                return self::encryptRSA4096($plaintext, $publicKeyPath);
            case 'hybrid':
                return self::encryptHybrid($plaintext, $publicKeyPath);
            case 'fullchain':
                return self::encryptFullChain($plaintext, $publicKeyPath);
            case 'triplelayer':
                return self::encryptTripleLayer($plaintext, $secretKey, $publicKeyPath);
            default:
                throw new Exception("Unknown method: $method");
        }
    }

    public static function decryptByMethod(string $method, string $ciphertext, string $secretKey = '', string $privateKeyPath = '', string $passphrase = ''): string
    {
        switch ($method) {
            case 'base64':
                return self::decodeBase64($ciphertext);
            case 'hex':
                return self::decodeHex($ciphertext);
            case 'aes-cbc':
                return self::decryptAES256CBC($ciphertext, $secretKey);
            case 'aes-gcm':
                return self::decryptAES256GCM($ciphertext, $secretKey);
            case 'aes-ctr':
                return self::decryptAES256CTR($ciphertext, $secretKey);
            case 'camellia':
                return self::decryptCamellia256CBC($ciphertext, $secretKey);
            case 'rsa':
                return self::decryptRSA4096($ciphertext, $privateKeyPath, $passphrase);
            case 'hybrid':
                return self::decryptHybrid($ciphertext, $privateKeyPath, $passphrase);
            case 'fullchain':
                return self::decryptFullChain($ciphertext, $privateKeyPath, $passphrase);
            case 'triplelayer':
                return self::decryptTripleLayer($ciphertext, $secretKey, $privateKeyPath, $passphrase);
            default:
                throw new Exception("Unknown method: $method");
        }
    }
}
