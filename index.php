<?php
// index.php
require_once __DIR__ . '/CryptoEngine.php';

$errors = [];
$result = null;
$timeTaken = null;
$resultSize = null;
$downloadPath = null;

function measure(callable $fn)
{
    $start = microtime(true);
    $res = $fn();
    $end = microtime(true);
    $time = $end - $start;
    $size = is_string($res) ? strlen($res) : 0;
    return [$res, $time, $size];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    $method = $_POST['method'] ?? 'aes-gcm';
    $secret = $_POST['secret'] ?? '';
    $publicKey = $_POST['public_key_path'] ?? ''; // can be path relative to project (optional)
    $privateKey = $_POST['private_key_path'] ?? '';
    $passphrase = $_POST['passphrase'] ?? '';

    try {
        if ($action === 'encrypt_text') {
            $plaintext = $_POST['plaintext'] ?? '';
            if ($plaintext === '')
                throw new Exception("Plaintext kosong.");
            list($out, $timeTaken, $resultSize) = measure(function () use ($method, $plaintext, $secret, $publicKey) {
                return CryptoEngine::encryptByMethod($method, $plaintext, $secret, $publicKey);
            });
            $result = $out;
        }

        if ($action === 'decrypt_text') {
            $ciphertext = $_POST['ciphertext'] ?? '';
            if ($ciphertext === '')
                throw new Exception("Ciphertext kosong.");
            list($out, $timeTaken, $resultSize) = measure(function () use ($method, $ciphertext, $secret, $privateKey, $passphrase) {
                return CryptoEngine::decryptByMethod($method, $ciphertext, $secret, $privateKey, $passphrase);
            });
            $result = $out;
        }

        if ($action === 'encrypt_file') {
            if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
                throw new Exception("Gagal upload file.");
            }
            $uploaded = $_FILES['file'];
            $tmp = $uploaded['tmp_name'];
            $data = file_get_contents($tmp);

            list($out, $timeTaken, $resultSize) = measure(function () use ($method, $data, $secret, $publicKey) {
                return CryptoEngine::encryptByMethod($method, $data, $secret, $publicKey);
            });

            // Simpan hasil sebagai file .enc agar bisa di-download
            $name = basename($uploaded['name']) . ".enc";
            $save = __DIR__ . '/uploads/' . uniqid('enc_') . '_' . preg_replace('/[^a-zA-Z0-9_\.\-]/', '_', $name);
            file_put_contents($save, $out);
            $downloadPath = 'uploads/' . basename($save);
            $result = "File terenkripsi tersimpan: <a href=\"$downloadPath\" download>Download</a>";
        }

        if ($action === 'decrypt_file') {
            if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
                throw new Exception("Gagal upload file.");
            }
            $uploaded = $_FILES['file'];
            $tmp = $uploaded['tmp_name'];
            $data = file_get_contents($tmp);

            list($out, $timeTaken, $resultSize) = measure(function () use ($method, $data, $secret, $privateKey, $passphrase) {
                return CryptoEngine::decryptByMethod($method, $data, $secret, $privateKey, $passphrase);
            });

            // Simpan hasil dekripsi ke file (restore original extension unknown; use .dec)
            $name = basename($uploaded['name']);
            $save = __DIR__ . '/uploads/' . uniqid('dec_') . '_' . preg_replace('/[^a-zA-Z0-9_\.\-]/', '_', $name) . '.dec';
            file_put_contents($save, $out);
            $downloadPath = 'uploads/' . basename($save);
            $result = "File ter-dekripsi tersimpan: <a href=\"$downloadPath\" download>Download</a>";
        }

    } catch (Exception $ex) {
        $errors[] = $ex->getMessage();
    }
}
?>
<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <title>Advanced Crypto System</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- Bootstrap 5 CSS CDN -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .card-header .title {
            font-weight: 600;
        }

        pre.output {
            background: #f8f9fa;
            padding: 12px;
            border-radius: 6px;
            max-height: 300px;
            overflow: auto;
        }

        .small-muted {
            font-size: 0.9rem;
            color: #6c757d;
        }
    </style>
</head>

<body>
    <div class="container my-4">
        <div class="p-3 mb-4 bg-primary text-white rounded">
            <h3 class="mb-0">Advanced Crypto System</h3>
            <small>Complete Encryption/Decryption Suite</small>
        </div>

        <?php if (!empty($errors)): ?>
            <div class="alert alert-danger">
                <?php foreach ($errors as $e)
                    echo "<div>$e</div>"; ?>
            </div>
        <?php endif; ?>

        <ul class="nav nav-tabs mb-3" id="mainTabs" role="tablist">
            <li class="nav-item"><a class="nav-link active" id="encrypt-tab" data-bs-toggle="tab" href="#encrypt"
                    role="tab">Encrypt</a></li>
            <li class="nav-item"><a class="nav-link" id="decrypt-tab" data-bs-toggle="tab" href="#decrypt"
                    role="tab">Decrypt</a></li>
        </ul>

        <div class="tab-content">
            <!-- ENCRYPT TAB -->
            <div class="tab-pane fade show active" id="encrypt" role="tabpanel">
                <div class="row">
                    <div class="col-md-6">
                        <div class="card mb-3">
                            <div class="card-header bg-primary text-white title">Encrypt Text</div>
                            <div class="card-body">
                                <form method="post">
                                    <input type="hidden" name="action" value="encrypt_text">
                                    <div class="mb-3">
                                        <label class="form-label">Plaintext</label>
                                        <textarea name="plaintext" class="form-control" rows="5"
                                            placeholder="Enter text to encrypt..."><?= isset($_POST['plaintext']) ? htmlspecialchars($_POST['plaintext']) : '' ?></textarea>
                                    </div>

                                    <div class="mb-3">
                                        <label class="form-label">Method</label>
                                        <select name="method" id="encMethodTxt" class="form-select">
                                            <optgroup label="Encoding (Not Encryption)">
                                                <option value="base64">Base64 Encoding</option>
                                                <option value="hex">Hexadecimal Encoding</option>
                                            </optgroup>
                                            <optgroup label="Hashing (One-way)">
                                                <option value="sha256">SHA-256 Hash</option>
                                                <option value="sha512">SHA-512 Hash</option>
                                                <option value="sha3-256">SHA3-256 Hash</option>
                                            </optgroup>
                                            <optgroup label="Symmetric Encryption">
                                                <option value="aes-gcm" selected>AES-256-GCM (Recommended)</option>
                                                <option value="aes-cbc">AES-256-CBC</option>
                                                <option value="aes-ctr">AES-256-CTR</option>
                                                <option value="camellia">Camellia-256-CBC</option>
                                            </optgroup>
                                            <optgroup label="Asymmetric & Hybrid">
                                                <option value="rsa">RSA-4096</option>
                                                <option value="hybrid">Hybrid (AES+RSA)</option>
                                                <option value="fullchain">Full-Chain (Hash+AES+RSA)</option>
                                                <option value="triplelayer">Triple-Layer (AES+Camellia+RSA)</option>
                                            </optgroup>
                                        </select>
                                    </div>

                                    <div class="mb-3 secret-input">
                                        <label class="form-label">Secret Key <span class="small-muted">(needed for
                                                AES/Camellia/Triple)</span></label>
                                        <input type="text" name="secret" class="form-control"
                                            placeholder="Enter secret key...">
                                    </div>

                                    <div class="mb-3 key-path">
                                        <label class="form-label">Public Key Path <span class="small-muted">(for
                                                RSA/Hybrid/Full/Triple)</span></label>
                                        <input type="text" name="public_key_path" class="form-control"
                                            placeholder="e.g. keys/public.pem">
                                    </div>

                                    <button class="btn btn-primary w-100"><i class="bi bi-lock"></i> Encrypt
                                        Text</button>
                                </form>
                            </div>
                        </div>

                        <!-- result area for text -->
                        <?php if ($result !== null && isset($_POST['action']) && $_POST['action'] === 'encrypt_text'): ?>
                            <div class="card border-success">
                                <div class="card-header">Result</div>
                                <div class="card-body text-success">
                                    <label class="form-label">Encrypted Output</label>
                                    <pre class="output"><?= htmlspecialchars($result) ?></pre>
                                    <div class="mt-2 small text-muted">
                                        ⏱️ Waktu enkripsi:
                                        <?= isset($timeTaken) ? round($timeTaken, 6) . " detik" : '-' ?><br>
                                        📦 Ukuran hasil:
                                        <?= isset($resultSize) ? $resultSize . " byte (" . round($resultSize / 1024, 2) . " KB)" : '-' ?>
                                    </div>
                                </div>
                            </div>
                        <?php endif; ?>
                    </div>

                    <!-- Encrypt File -->
                    <div class="col-md-6">
                        <div class="card mb-3">
                            <div class="card-header bg-primary text-white title">Encrypt File</div>
                            <div class="card-body">
                                <form method="post" enctype="multipart/form-data">
                                    <input type="hidden" name="action" value="encrypt_file">
                                    <div class="mb-3">
                                        <label class="form-label">Choose File</label>
                                        <input type="file" name="file" class="form-control">
                                        <div class="small-muted mt-1">Max: depends on php.ini upload_max_filesize</div>
                                    </div>

                                    <div class="mb-3">
                                        <label class="form-label">Method</label>
                                        <select name="method" class="form-select">
                                            <optgroup label="Encoding">
                                                <option value="base64">Base64 Encoding</option>
                                                <option value="hex">Hexadecimal Encoding</option>
                                            </optgroup>
                                            <optgroup label="Symmetric">
                                                <option value="aes-gcm" selected>AES-256-GCM (Recommended)</option>
                                                <option value="aes-cbc">AES-256-CBC</option>
                                                <option value="aes-ctr">AES-256-CTR</option>
                                                <option value="camellia">Camellia-256-CBC</option>
                                            </optgroup>
                                            <optgroup label="Asymmetric & Hybrid">
                                                <option value="rsa">RSA-4096</option>
                                                <option value="hybrid">Hybrid (AES+RSA)</option>
                                                <option value="fullchain">Full-Chain (Hash+AES+RSA)</option>
                                                <option value="triplelayer">Triple-Layer (AES+Camellia+RSA)</option>
                                            </optgroup>
                                        </select>
                                    </div>

                                    <div class="mb-3">
                                        <label class="form-label">Secret Key</label>
                                        <input type="text" name="secret" class="form-control"
                                            placeholder="Enter secret key...">
                                    </div>

                                    <div class="mb-3">
                                        <label class="form-label">Public Key Path</label>
                                        <input type="text" name="public_key_path" class="form-control"
                                            placeholder="e.g. keys/public.pem">
                                    </div>

                                    <button class="btn btn-primary w-100">🔒 Encrypt File</button>
                                </form>
                            </div>
                        </div>

                        <!-- result area for file -->
                        <?php if ($result !== null && isset($_POST['action']) && $_POST['action'] === 'encrypt_file'): ?>
                            <div class="card border-success">
                                <div class="card-header">Result</div>
                                <div class="card-body text-success">
                                    <div><?= $result ?></div>
                                    <div class="mt-2 small text-muted">
                                        ⏱️ Waktu enkripsi:
                                        <?= isset($timeTaken) ? round($timeTaken, 6) . " detik" : '-' ?><br>
                                        📦 Ukuran hasil:
                                        <?= isset($resultSize) ? $resultSize . " byte (" . round($resultSize / 1024, 2) . " KB)" : '-' ?>
                                    </div>
                                </div>
                            </div>
                        <?php endif; ?>

                    </div>
                </div>
            </div>

            <!-- DECRYPT TAB -->
            <div class="tab-pane fade" id="decrypt" role="tabpanel">
                <div class="row">
                    <div class="col-md-6">
                        <div class="card mb-3">
                            <div class="card-header bg-success text-white title">Decrypt Text</div>
                            <div class="card-body">
                                <form method="post">
                                    <input type="hidden" name="action" value="decrypt_text">
                                    <div class="mb-3">
                                        <label class="form-label">Encrypted Text</label>
                                        <textarea name="ciphertext" class="form-control" rows="5"
                                            placeholder="Paste encrypted text here..."><?= isset($_POST['ciphertext']) ? htmlspecialchars($_POST['ciphertext']) : '' ?></textarea>
                                    </div>

                                    <div class="mb-3">
                                        <label class="form-label">Method</label>
                                        <select name="method" class="form-select">
                                            <option value="aes-gcm" selected>AES-256-GCM</option>
                                            <option value="aes-cbc">AES-256-CBC</option>
                                            <option value="aes-ctr">AES-256-CTR</option>
                                            <option value="camellia">Camellia-256-CBC</option>
                                            <option value="base64">Base64</option>
                                            <option value="hex">Hex</option>
                                            <option value="rsa">RSA-4096</option>
                                            <option value="hybrid">Hybrid (AES+RSA)</option>
                                            <option value="fullchain">Full-Chain</option>
                                            <option value="triplelayer">Triple-Layer</option>
                                        </select>
                                    </div>

                                    <div class="mb-3">
                                        <label class="form-label">Secret Key</label>
                                        <input type="text" name="secret" class="form-control"
                                            placeholder="Enter secret key...">
                                    </div>

                                    <div class="mb-3">
                                        <label class="form-label">Private Key Path</label>
                                        <input type="text" name="private_key_path" class="form-control"
                                            placeholder="e.g. keys/private.pem">
                                    </div>

                                    <div class="mb-3">
                                        <label class="form-label">Passphrase (optional)</label>
                                        <input type="text" name="passphrase" class="form-control"
                                            placeholder="Passphrase for private key (if any)">
                                    </div>

                                    <button class="btn btn-success w-100">🔓 Decrypt Text</button>
                                </form>
                            </div>
                        </div>

                        <?php if ($result !== null && isset($_POST['action']) && $_POST['action'] === 'decrypt_text'): ?>
                            <div class="card border-primary">
                                <div class="card-header">Result</div>
                                <div class="card-body text-primary">
                                    <label class="form-label">Decrypted Output</label>
                                    <pre class="output"><?= htmlspecialchars($result) ?></pre>
                                    <div class="mt-2 small text-muted">
                                        ⏱️ Waktu dekripsi:
                                        <?= isset($timeTaken) ? round($timeTaken, 6) . " detik" : '-' ?><br>
                                        📦 Ukuran hasil:
                                        <?= isset($resultSize) ? $resultSize . " byte (" . round($resultSize / 1024, 2) . " KB)" : '-' ?>
                                    </div>
                                </div>
                            </div>
                        <?php endif; ?>

                    </div>

                    <div class="col-md-6">
                        <div class="card mb-3">
                            <div class="card-header bg-success text-white title">Decrypt File</div>
                            <div class="card-body">
                                <form method="post" enctype="multipart/form-data">
                                    <input type="hidden" name="action" value="decrypt_file">
                                    <div class="mb-3">
                                        <label class="form-label">Encrypted File (.enc)</label>
                                        <input type="file" name="file" class="form-control">
                                    </div>

                                    <div class="mb-3">
                                        <label class="form-label">Method</label>
                                        <select name="method" class="form-select">
                                            <option value="aes-gcm" selected>AES-256-GCM</option>
                                            <option value="aes-cbc">AES-256-CBC</option>
                                            <option value="aes-ctr">AES-256-CTR</option>
                                            <option value="camellia">Camellia-256-CBC</option>
                                            <option value="rsa">RSA-4096</option>
                                            <option value="hybrid">Hybrid (AES+RSA)</option>
                                            <option value="fullchain">Full-Chain</option>
                                            <option value="triplelayer">Triple-Layer</option>
                                            <option value="base64">Base64</option>
                                            <option value="hex">Hex</option>
                                        </select>
                                    </div>

                                    <div class="mb-3">
                                        <label class="form-label">Secret Key</label>
                                        <input type="text" name="secret" class="form-control"
                                            placeholder="Enter secret key...">
                                    </div>

                                    <div class="mb-3">
                                        <label class="form-label">Private Key Path</label>
                                        <input type="text" name="private_key_path" class="form-control"
                                            placeholder="e.g. keys/private.pem">
                                    </div>

                                    <div class="mb-3">
                                        <label class="form-label">Passphrase (optional)</label>
                                        <input type="text" name="passphrase" class="form-control"
                                            placeholder="Passphrase for private key (if any)">
                                    </div>

                                    <button class="btn btn-success w-100">🔓 Decrypt File</button>
                                </form>
                            </div>
                        </div>

                        <?php if ($result !== null && isset($_POST['action']) && $_POST['action'] === 'decrypt_file'): ?>
                            <div class="card border-primary">
                                <div class="card-header">Result</div>
                                <div class="card-body text-primary">
                                    <div><?= $result ?></div>
                                    <div class="mt-2 small text-muted">
                                        ⏱️ Waktu dekripsi:
                                        <?= isset($timeTaken) ? round($timeTaken, 6) . " detik" : '-' ?><br>
                                        📦 Ukuran hasil:
                                        <?= isset($resultSize) ? $resultSize . " byte (" . round($resultSize / 1024, 2) . " KB)" : '-' ?>
                                    </div>
                                </div>
                            </div>
                        <?php endif; ?>

                    </div>
                </div>
            </div>

        </div>
    </div>

    <!-- Bootstrap JS (bundle includes Popper) -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // small UI logic: show/hide secret & key inputs could be added if desired
    </script>
</body>

</html>