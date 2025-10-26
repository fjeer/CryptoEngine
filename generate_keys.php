<?php

/**
 * GENERATE KEYS - API Endpoint for RSA Key Management
 */

require_once 'config.php';
header('Content-Type: application/json');

// POST: Generate new key pair
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $keySize = isset($_POST['key_size']) ? (int)$_POST['key_size'] : 4096;
    $passphrase = isset($_POST['passphrase']) ? $_POST['passphrase'] : '';
    $keyName = isset($_POST['key_name']) ? $_POST['key_name'] : '';

    if (!in_array($keySize, [2048, 4096])) {
        echo json_encode(['success' => false, 'error' => 'Invalid key size']);
        exit;
    }

    $result = KeyManager::generateKeyPair($keySize, $passphrase, $keyName);
    echo json_encode($result);
    exit;
}

// GET: List all key pairs
elseif ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $keys = KeyManager::listKeyPairs();
    echo json_encode([
        'success' => true,
        'keys' => $keys,
        'count' => count($keys)
    ]);
    exit;
}

// DELETE: Delete key pair
elseif ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
    parse_str(file_get_contents('php://input'), $_DELETE);
    $keyName = isset($_DELETE['keyname']) ? $_DELETE['keyname'] : '';

    if (empty($keyName)) {
        echo json_encode(['success' => false, 'error' => 'Key name required']);
        exit;
    }

    $deleted = KeyManager::deleteKeyPair($keyName);

    if ($deleted) {
        echo json_encode(['success' => true, 'message' => 'Key pair deleted']);
    } else {
        echo json_encode(['success' => false, 'error' => 'Key pair not found']);
    }
    exit;
} else {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    exit;
}
