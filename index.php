<?php require_once 'config.php'; ?>
<!DOCTYPE html>
<html lang="id">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced Crypto System - PHP Encryption Suite</title>

    <!-- Bootstrap 5 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">

    <!-- Bootstrap Icons -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css" rel="stylesheet">
</head>

<body class="bg-light">
    <div class="container py-4">

        <!-- Header -->
        <div class="bg-primary text-white p-4 rounded mb-4">
            <h1 class="mb-2"><i class="bi bi-shield-lock-fill"></i> Advanced Crypto System</h1>
            <p class="mb-0">Complete Encryption/Decryption Suite with Multiple Algorithms</p>
        </div>

        <!-- Navigation Tabs -->
        <ul class="nav nav-tabs mb-4" role="tablist">
            <li class="nav-item">
                <button class="nav-link active" data-bs-toggle="tab" data-bs-target="#encrypt">
                    <i class="bi bi-lock-fill"></i> Encrypt
                </button>
            </li>
            <li class="nav-item">
                <button class="nav-link" data-bs-toggle="tab" data-bs-target="#decrypt">
                    <i class="bi bi-unlock-fill"></i> Decrypt
                </button>
            </li>
            <li class="nav-item">
                <button class="nav-link" data-bs-toggle="tab" data-bs-target="#keys">
                    <i class="bi bi-key-fill"></i> Key Manager
                </button>
            </li>
            <li class="nav-item">
                <button class="nav-link" data-bs-toggle="tab" data-bs-target="#guide">
                    <i class="bi bi-book-fill"></i> Guide
                </button>
            </li>
            <li class="nav-item">
                <button class="nav-link" data-bs-toggle="tab" data-bs-target="#system">
                    <i class="bi bi-gear-fill"></i> System
                </button>
            </li>
        </ul>

        <!-- Tab Contents -->
        <div class="tab-content">

            <!-- ========================================== -->
            <!-- ENCRYPT TAB -->
            <!-- ========================================== -->
            <div class="tab-pane fade show active" id="encrypt">
                <div class="row">
                    <div class="col-md-6 mb-4">
                        <div class="card">
                            <div class="card-header bg-primary text-white">
                                <i class="bi bi-file-text"></i> Encrypt Text
                            </div>
                            <div class="card-body">
                                <form id="encryptTextForm">
                                    <div class="mb-3">
                                        <label class="form-label">Plaintext</label>
                                        <textarea class="form-control" name="plaintext" rows="4" required placeholder="Enter text to encrypt..."></textarea>
                                    </div>

                                    <div class="mb-3">
                                        <label class="form-label">Method</label>
                                        <select class="form-select" name="method" id="encryptTextMethod" required>
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
                                                <option value="camellia">Camellia-256-CBC</option>
                                            </optgroup>
                                            <optgroup label="Asymmetric & Hybrid">
                                                <option value="rsa">RSA-4096 (Max ~446 bytes)</option>
                                                <option value="hybrid">Hybrid (AES+RSA)</option>
                                                <option value="fullchain">Full-Chain (Hash+AES+RSA)</option>
                                                <option value="triplelayer">Triple-Layer (AES+Camellia+RSA)</option>
                                            </optgroup>
                                        </select>
                                    </div>

                                    <div class="mb-3" id="encryptTextSecretKeyGroup">
                                        <label class="form-label">Secret Key</label>
                                        <input type="text" class="form-control" name="secret_key" placeholder="Enter secret key...">
                                        <small class="text-muted">Required for AES, Camellia, Triple-Layer</small>
                                    </div>

                                    <div class="mb-3 d-none" id="encryptTextPublicKeyGroup">
                                        <label class="form-label">Public Key</label>
                                        <select class="form-select" name="public_key" id="encryptTextPublicKey">
                                            <option value="">-- Select Public Key --</option>
                                            <option value="mykey">mykey</option>
                                        </select>
                                        <small class="text-muted">Required for RSA, Hybrid, Full-Chain, Triple-Layer</small>
                                    </div>

                                    <button type="submit" class="btn btn-primary w-100">
                                        <i class="bi bi-lock-fill"></i> Encrypt Text
                                    </button>
                                </form>

                                <div id="encryptTextResult" class="mt-3 d-none">
                                    <hr>
                                    <h6>Encrypted Result:</h6>
                                    <div class="alert alert-success">
                                        <strong>Method:</strong> <span id="encryptTextResultMethod"></span>
                                        <div id="encryptTextResultInfo" class="mt-2 text-muted small"></div>
                                    </div>
                                    <div class="mb-2">
                                        <label class="form-label">Encrypted Data:</label>
                                        <textarea class="form-control" id="encryptTextResultData" rows="4" readonly></textarea>
                                        <button type="button" class="btn btn-sm btn-secondary mt-2" onclick="copyToClipboard('encryptTextResultData')">
                                            <i class="bi bi-clipboard"></i> Copy
                                        </button>
                                    </div>
                                    <div id="encryptTextResultKeyGroup" class="d-none">
                                        <label class="form-label">Encrypted Key:</label>
                                        <textarea class="form-control" id="encryptTextResultKey" rows="3" readonly></textarea>
                                        <button type="button" class="btn btn-sm btn-secondary mt-2" onclick="copyToClipboard('encryptTextResultKey')">
                                            <i class="bi bi-clipboard"></i> Copy
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="col-md-6 mb-4">
                        <div class="card">
                            <div class="card-header bg-primary text-white">
                                <i class="bi bi-file-earmark-lock"></i> Encrypt File
                            </div>
                            <div class="card-body">
                                <form id="encryptFileForm">
                                    <div class="mb-3">
                                        <label class="form-label">Choose File</label>
                                        <input type="file" class="form-control" name="file" required>
                                        <small class="text-muted">Max: <?= formatFileSize(MAX_FILE_SIZE) ?></small>
                                    </div>

                                    <div class="mb-3">
                                        <label class="form-label">Method</label>
                                        <select class="form-select" name="method" id="encryptFileMethod" required>
                                            <optgroup label="Encoding">
                                                <option value="base64">Base64 Encoding</option>
                                                <option value="hex">Hexadecimal Encoding</option>
                                            </optgroup>
                                            <optgroup label="Symmetric Encryption">
                                                <option value="aes-gcm" selected>AES-256-GCM (Recommended)</option>
                                                <option value="aes-cbc">AES-256-CBC</option>
                                                <option value="camellia">Camellia-256-CBC</option>
                                            </optgroup>
                                            <optgroup label="Asymmetric & Hybrid">
                                                <option value="hybrid">Hybrid (AES+RSA)</option>
                                                <option value="fullchain">Full-Chain (Hash+AES+RSA)</option>
                                                <option value="triplelayer">Triple-Layer (AES+Camellia+RSA)</option>
                                            </optgroup>
                                        </select>
                                    </div>

                                    <div class="mb-3" id="encryptFileSecretKeyGroup">
                                        <label class="form-label">Secret Key</label>
                                        <input type="text" class="form-control" name="secret_key" placeholder="Enter secret key...">
                                    </div>

                                    <div class="mb-3 d-none" id="encryptFilePublicKeyGroup">
                                        <label class="form-label">Public Key</label>
                                        <select class="form-select" name="public_key" id="encryptFilePublicKey">
                                            <option value="">-- Select Public Key --</option>
                                        </select>
                                    </div>

                                    <button type="submit" class="btn btn-primary w-100">
                                        <i class="bi bi-lock-fill"></i> Encrypt File
                                    </button>
                                </form>

                               <div id="encryptFileResult" class="mt-3 d-none">
    <hr>
                            <div class="alert alert-success">
                                <h6>File Encrypted Successfully!</h6>
                                <p class="mb-1"><strong>Method:</strong> <span id="encryptFileResultMethod"></span></p>
                                <p class="mb-1"><strong>File:</strong> <span id="encryptFileResultName"></span></p>
                                <p class="mb-1"><strong>Original Size:</strong> <span id="encryptFileResultOriginalSize"></span> KB</p>
                                <p class="mb-1"><strong>Encrypted Size:</strong> <span id="encryptFileResultEncryptedSize"></span> KB</p>
                                <p class="mb-0"><strong>Encryption Time:</strong> <span id="encryptFileResultTime"></span> detik</p>
                                </div>
                                    <a href="#" id="encryptFileResultDownload" class="btn btn-success w-100" target="_blank">
                                        <i class="bi bi-download"></i> Download Encrypted File
                                    </a>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- ========================================== -->
            <!-- DECRYPT TAB -->
            <!-- ========================================== -->
            <div class="tab-pane fade" id="decrypt">
                <div class="row">
                    <div class="col-md-6 mb-4">
                        <div class="card">
                            <div class="card-header bg-success text-white">
                                <i class="bi bi-file-text"></i> Decrypt Text
                            </div>
                            <div class="card-body">
                                <form id="decryptTextForm">
                                    <div class="mb-3">
                                        <label class="form-label">Encrypted Text</label>
                                        <textarea class="form-control" name="encrypted_text" rows="4" required placeholder="Paste encrypted text here..."></textarea>
                                    </div>

                                    <div class="mb-3">
                                        <label class="form-label">Method</label>
                                        <select class="form-select" name="method" id="decryptTextMethod" required>
                                            <optgroup label="Encoding">
                                                <option value="base64">Base64 Decoding</option>
                                                <option value="hex">Hexadecimal Decoding</option>
                                            </optgroup>
                                            <optgroup label="Symmetric Decryption">
                                                <option value="aes-gcm" selected>AES-256-GCM</option>
                                                <option value="aes-cbc">AES-256-CBC</option>
                                                <option value="camellia">Camellia-256-CBC</option>
                                            </optgroup>
                                            <optgroup label="Asymmetric & Hybrid">
                                                <option value="rsa">RSA-4096</option>
                                                <option value="hybrid">Hybrid (AES+RSA)</option>
                                                <option value="fullchain">Full-Chain</option>
                                                <option value="triplelayer">Triple-Layer</option>
                                            </optgroup>
                                        </select>
                                    </div>

                                    <div class="mb-3" id="decryptTextSecretKeyGroup">
                                        <label class="form-label">Secret Key</label>
                                        <input type="text" class="form-control" name="secret_key" placeholder="Enter secret key...">
                                    </div>

                                    <div class="mb-3 d-none" id="decryptTextPrivateKeyGroup">
                                        <label class="form-label">Private Key</label>
                                        <select class="form-select" name="private_key" id="decryptTextPrivateKey">
                                            <option value="">-- Select Private Key --</option>
                                        </select>
                                    </div>

                                    <div class="mb-3 d-none" id="decryptTextPassphraseGroup">
                                        <label class="form-label">Passphrase (if protected)</label>
                                        <input type="password" class="form-control" name="passphrase" placeholder="Enter passphrase...">
                                    </div>

                                    <div class="mb-3 d-none" id="decryptTextEncryptedKeyGroup">
                                        <label class="form-label">Encrypted Key</label>
                                        <textarea class="form-control" name="encrypted_key" rows="3" placeholder="Paste encrypted key..."></textarea>
                                    </div>

                                    <button type="submit" class="btn btn-success w-100">
                                        <i class="bi bi-unlock-fill"></i> Decrypt Text
                                    </button>
                                </form>

                                <div id="decryptTextResult" class="mt-3 d-none">
                                    <hr>
                                    <h6>Decrypted Result:</h6>
                                    <div class="alert alert-success">Decryption successful!</div>
                                    <textarea class="form-control" id="decryptTextResultData" rows="6" readonly></textarea>
                                    <button type="button" class="btn btn-sm btn-secondary mt-2" onclick="copyToClipboard('decryptTextResultData')">
                                        <i class="bi bi-clipboard"></i> Copy
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="col-md-6 mb-4">
                        <div class="card">
                            <div class="card-header bg-success text-white">
                                <i class="bi bi-file-earmark-lock"></i> Decrypt File
                            </div>
                            <div class="card-body">
                                <form id="decryptFileForm">
                                    <div class="mb-3">
                                        <label class="form-label">Encrypted File (.enc)</label>
                                        <input type="file" class="form-control" name="encrypted_file" accept=".enc" required>
                                    </div>

                                    <button type="button" class="btn btn-info w-100 mb-3" id="checkMethodBtn">
                                        <i class="bi bi-search"></i> Auto-Detect Method
                                    </button>

                                    <div id="fileMethodInfo" class="alert alert-info d-none">
                                        <strong>Detected Method:</strong> <span id="detectedMethod"></span><br>
                                        <strong>Original File:</strong> <span id="detectedOriginalName"></span>
                                    </div>

                                    <div class="mb-3">
                                        <label class="form-label">Method</label>
                                        <select class="form-select" name="method" id="decryptFileMethod" required>
                                            <optgroup label="Encoding">
                                                <option value="base64">Base64</option>
                                                <option value="hex">Hexadecimal</option>
                                            </optgroup>
                                            <optgroup label="Symmetric">
                                                <option value="aes-gcm" selected>AES-256-GCM</option>
                                                <option value="aes-cbc">AES-256-CBC</option>
                                                <option value="camellia">Camellia-256-CBC</option>
                                            </optgroup>
                                            <optgroup label="Asymmetric & Hybrid">
                                                <option value="rsa">RSA-4096</option>
                                                <option value="hybrid">Hybrid</option>
                                                <option value="fullchain">Full-Chain</option>
                                                <option value="triplelayer">Triple-Layer</option>
                                            </optgroup>
                                        </select>
                                    </div>

                                    <div class="mb-3" id="decryptFileSecretKeyGroup">
                                        <label class="form-label">Secret Key</label>
                                        <input type="text" class="form-control" name="secret_key" placeholder="Enter secret key...">
                                    </div>

                                    <div class="mb-3 d-none" id="decryptFilePrivateKeyGroup">
                                        <label class="form-label">Private Key</label>
                                        <select class="form-select" name="private_key" id="decryptFilePrivateKey">
                                            <option value="">-- Select Private Key --</option>
                                        </select>
                                    </div>

                                    <div class="mb-3 d-none" id="decryptFilePassphraseGroup">
                                        <label class="form-label">Passphrase</label>
                                        <input type="password" class="form-control" name="passphrase" placeholder="Enter passphrase...">
                                    </div>

                                    <button type="submit" class="btn btn-success w-100">
                                        <i class="bi bi-unlock-fill"></i> Decrypt File
                                    </button>
                                </form>

                                <div id="decryptFileResult" class="mt-3 d-none">
                                    <hr>
                                    <div class="alert alert-success">
                                        <h6>File Decrypted Successfully!</h6>
                                        <p class="mb-0"><strong>File:</strong> <span id="decryptFileResultName"></span></p>
                                    </div>

                                    <div id="decryptFilePreview" class="d-none mb-3">
                                        <h6>Preview:</h6>
                                        <div id="decryptFilePreviewContent" class="border rounded p-2"></div>
                                    </div>

                                    <a href="#" id="decryptFileResultDownload" class="btn btn-success w-100" target="_blank">
                                        <i class="bi bi-download"></i> Download Decrypted File
                                    </a>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- ========================================== -->
            <!-- KEYS TAB -->
            <!-- ========================================== -->
            <div class="tab-pane fade" id="keys">
                <div class="row">
                    <div class="col-md-5 mb-4">
                        <div class="card">
                            <div class="card-header bg-warning text-dark">
                                <i class="bi bi-plus-circle"></i> Generate New Key Pair
                            </div>
                            <div class="card-body">
                                <form id="generateKeyForm">
                                    <div class="mb-3">
                                        <label class="form-label">Key Name</label>
                                        <input type="text" class="form-control" name="key_name" placeholder="my_key (optional)">
                                        <small class="text-muted">Leave blank for auto-generated name</small>
                                    </div>

                                    <div class="mb-3">
                                        <label class="form-label">Key Size</label>
                                        <select class="form-select" name="key_size" required>
                                            <option value="2048">2048 bits (Fast)</option>
                                            <option value="4096" selected>4096 bits (Recommended)</option>
                                        </select>
                                    </div>

                                    <div class="mb-3">
                                        <label class="form-label">Passphrase (Optional)</label>
                                        <input type="password" class="form-control" name="passphrase" placeholder="Protect private key">
                                        <small class="text-muted">Recommended for production use</small>
                                    </div>

                                    <button type="submit" class="btn btn-warning w-100">
                                        <i class="bi bi-key-fill"></i> Generate Key Pair
                                    </button>
                                </form>

                                <div id="generateKeyResult" class="mt-3 d-none">
                                    <hr>
                                    <div class="alert alert-success">
                                        <h6>Key Pair Generated!</h6>
                                        <p class="mb-1"><strong>Method:</strong> <span id="keyGenMethod"></span></p>
                                        <p class="mb-1"><strong>Name:</strong> <span id="keyGenName"></span></p>
                                        <p class="mb-0"><strong>Size:</strong> <span id="keyGenSize"></span> bits</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="col-md-7 mb-4">
                        <div class="card">
                            <div class="card-header bg-info text-white">
                                <i class="bi bi-list"></i> Available Key Pairs
                                <button class="btn btn-sm btn-light float-end" onclick="loadKeyPairs()">
                                    <i class="bi bi-arrow-clockwise"></i> Refresh
                                </button>
                            </div>
                            <div class="card-body">
                                <div id="keyPairsList">
                                    <div class="text-center text-muted">
                                        <i class="bi bi-hourglass-split"></i> Loading...
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- ========================================== -->
            <!-- GUIDE TAB -->
            <!-- ========================================== -->
            <div class="tab-pane fade" id="guide">
                <div class="card">
                    <div class="card-header bg-dark text-white">
                        <i class="bi bi-book"></i> Quick Guide
                    </div>
                    <div class="card-body">
                        <h5>Available Methods</h5>

                        <div class="accordion" id="methodsAccordion">
                            <div class="accordion-item">
                                <h2 class="accordion-header">
                                    <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#methodEncoding">
                                        Encoding (Not Encryption)
                                    </button>
                                </h2>
                                <div id="methodEncoding" class="accordion-collapse collapse show" data-bs-parent="#methodsAccordion">
                                    <div class="accordion-body">
                                        <ul>
                                            <li><strong>Base64:</strong> Simple encoding, not secure</li>
                                            <li><strong>Hexadecimal:</strong> Binary to hex conversion</li>
                                        </ul>
                                    </div>
                                </div>
                            </div>

                            <div class="accordion-item">
                                <h2 class="accordion-header">
                                    <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#methodHash">
                                        Hashing (One-way)
                                    </button>
                                </h2>
                                <div id="methodHash" class="accordion-collapse collapse" data-bs-parent="#methodsAccordion">
                                    <div class="accordion-body">
                                        <ul>
                                            <li><strong>SHA-256:</strong> 256-bit hash (cannot be decrypted)</li>
                                            <li><strong>SHA-512:</strong> 512-bit hash (cannot be decrypted)</li>
                                            <li><strong>SHA3-256:</strong> Modern SHA-3 variant</li>
                                        </ul>
                                        <div class="alert alert-warning">
                                            <i class="bi bi-exclamation-triangle"></i> Hash functions are one-way and cannot be decrypted!
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div class="accordion-item">
                                <h2 class="accordion-header">
                                    <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#methodSymmetric">
                                        Symmetric Encryption
                                    </button>
                                </h2>
                                <div id="methodSymmetric" class="accordion-collapse collapse" data-bs-parent="#methodsAccordion">
                                    <div class="accordion-body">
                                        <ul>
                                            <li><strong>AES-256-GCM:</strong> Modern, authenticated encryption (RECOMMENDED)</li>
                                            <li><strong>AES-256-CBC:</strong> Classic AES with HMAC verification</li>
                                            <li><strong>Camellia-256:</strong> Alternative to AES</li>
                                        </ul>
                                        <p><strong>Requires:</strong> Secret key (same for encryption & decryption)</p>
                                    </div>
                                </div>
                            </div>

                            <div class="accordion-item">
                                <h2 class="accordion-header">
                                    <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#methodAsymmetric">
                                        Asymmetric & Hybrid
                                    </button>
                                </h2>
                                <div id="methodAsymmetric" class="accordion-collapse collapse" data-bs-parent="#methodsAccordion">
                                    <div class="accordion-body">
                                        <ul>
                                            <li><strong>RSA-4096:</strong> Public/private key encryption (max ~446 bytes)</li>
                                            <li><strong>Hybrid:</strong> AES-256-GCM + RSA-4096 (BEST for large data)</li>
                                            <li><strong>Full-Chain:</strong> SHA-256 + AES-256-GCM + RSA-4096 (with integrity check)</li>
                                            <li><strong>Triple-Layer:</strong> AES-CBC + Camellia + RSA (maximum security)</li>
                                        </ul>
                                        <p><strong>Requires:</strong> Public key (encrypt) & Private key (decrypt)</p>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <hr>

                        <h5>Usage Steps</h5>
                        <ol>
                            <li>For RSA/Hybrid methods: Generate a key pair first in the "Key Manager" tab</li>
                            <li>Choose your encryption method based on your needs</li>
                            <li>For symmetric methods: Use a strong secret key</li>
                            <li>For asymmetric methods: Select the appropriate public/private key</li>
                            <li>Save the encrypted output and keys safely</li>
                            <li>To decrypt, use the same method and corresponding keys</li>
                        </ol>

                        <div class="alert alert-info">
                            <i class="bi bi-lightbulb"></i> <strong>Recommendation:</strong> Use <strong>Hybrid</strong> or <strong>Full-Chain</strong> for best security with any data size.
                        </div>
                    </div>
                </div>
            </div>

            <!-- ========================================== -->
            <!-- SYSTEM TAB -->
            <!-- ========================================== -->
            <div class="tab-pane fade" id="system">
                <div class="card">
                    <div class="card-header bg-secondary text-white">
                        <i class="bi bi-info-circle"></i> System Information
                    </div>
                    <div class="card-body">
                        <h5>Requirements Check</h5>
                        <table class="table table-bordered">
                            <thead>
                                <tr>
                                    <th>Component</th>
                                    <th>Required</th>
                                    <th>Current</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php
                                $requirements = checkSystemRequirements();
                                foreach ($requirements as $name => $req):
                                    $statusClass = $req['check'] ? 'success' : ($req['critical'] ? 'danger' : 'warning');
                                    $statusIcon = $req['check'] ? 'check-circle-fill' : 'x-circle-fill';
                                ?>
                                    <tr class="table-<?= $statusClass ?>">
                                        <td><?= ucfirst(str_replace('_', ' ', $name)) ?></td>
                                        <td>
                                            <?php if (isset($req['required'])): ?>
                                                <?= $req['required'] ?>
                                            <?php elseif (isset($req['description'])): ?>
                                                <?= $req['description'] ?>
                                            <?php else: ?>
                                                Enabled
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <?php if (isset($req['current'])): ?>
                                                <?= $req['current'] ?>
                                            <?php else: ?>
                                                <?= $req['check'] ? 'Installed' : 'Not Installed' ?>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <i class="bi bi-<?= $statusIcon ?>"></i>
                                            <?= $req['check'] ? 'OK' : 'Failed' ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>

                        <hr>

                        <h5>Configuration</h5>
                        <ul>
                            <li><strong>Max File Size:</strong> <?= formatFileSize(MAX_FILE_SIZE) ?></li>
                            <li><strong>Keys Directory:</strong> <?= KEYS_DIR ?></li>
                            <li><strong>Timezone:</strong> <?= date_default_timezone_get() ?></li>
                            <li><strong>PHP Version:</strong> <?= PHP_VERSION ?></li>
                        </ul>

                        <hr>

                        <h5>Security Notes</h5>
                        <div class="alert alert-warning">
                            <ul class="mb-0">
                                <li>Always use strong, random keys for encryption</li>
                                <li>Keep private keys and passphrases secure</li>
                                <li>Use HTTPS in production environments</li>
                                <li>Regularly backup your keys</li>
                                <li>For production: Set appropriate file permissions</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>

        </div>
    </div>

    <!-- Bootstrap 5 JS Bundle -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>

    <script>
        // ==========================================
        // UTILITY FUNCTIONS
        // ==========================================

        function showAlert(message, type = 'danger') {
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert alert-${type} alert-dismissible fade show position-fixed top-0 start-50 translate-middle-x mt-3`;
            alertDiv.style.zIndex = '9999';
            alertDiv.innerHTML = `
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            `;
            document.body.appendChild(alertDiv);

            setTimeout(() => {
                alertDiv.remove();
            }, 5000);
        }

        function copyToClipboard(elementId) {
            const element = document.getElementById(elementId);
            element.select();
            document.execCommand('copy');
            showAlert('Copied to clipboard!', 'success');
        }

        function toggleFieldVisibility(method, prefix) {
            const secretKeyGroup = document.getElementById(`${prefix}SecretKeyGroup`);
            const publicKeyGroup = document.getElementById(`${prefix}PublicKeyGroup`);
            const privateKeyGroup = document.getElementById(`${prefix}PrivateKeyGroup`);
            const passphraseGroup = document.getElementById(`${prefix}PassphraseGroup`);
            const encryptedKeyGroup = document.getElementById(`${prefix}EncryptedKeyGroup`);

            const needsSecretKey = ['aes-cbc', 'aes-gcm', 'aes', 'aes-ctr', 'camellia', 'triplelayer'];
            const needsPublicKey = ['rsa', 'hybrid', 'fullchain', 'triplelayer'];
            const needsPrivateKey = ['rsa', 'hybrid', 'fullchain', 'triplelayer'];
            const needsEncryptedKey = ['hybrid', 'fullchain', 'triplelayer'];

            if (secretKeyGroup) {
                secretKeyGroup.classList.toggle('d-none', !needsSecretKey.includes(method));
            }
            if (publicKeyGroup) {
                publicKeyGroup.classList.toggle('d-none', !needsPublicKey.includes(method));
            }
            if (privateKeyGroup) {
                privateKeyGroup.classList.toggle('d-none', !needsPrivateKey.includes(method));
            }
            if (passphraseGroup) {
                passphraseGroup.classList.toggle('d-none', !needsPrivateKey.includes(method));
            }
            if (encryptedKeyGroup) {
                encryptedKeyGroup.classList.toggle('d-none', !needsEncryptedKey.includes(method));
            }
        }

        // ==========================================
        // LOAD KEY PAIRS
        // ==========================================

        function loadKeyPairs() {
            fetch('generate_keys.php')
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        updateKeyPairsList(data.keys);
                        updateKeyDropdowns(data.keys);
                    } else {
                        document.getElementById('keyPairsList').innerHTML =
                            '<div class="alert alert-danger">Failed to load keys</div>';
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    document.getElementById('keyPairsList').innerHTML =
                        '<div class="alert alert-danger">Error loading keys</div>';
                });
        }

        function updateKeyPairsList(keys) {
            const container = document.getElementById('keyPairsList');

            if (keys.length === 0) {
                container.innerHTML = '<div class="text-muted text-center">No key pairs found. Generate one first!</div>';
                return;
            }

            let html = '<div class="list-group">';
            keys.forEach(key => {
                html += `
                    <div class="list-group-item">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <h6 class="mb-1"><i class="bi bi-key-fill"></i> ${key.name}</h6>
                                <small class="text-muted">Size: ${key.size} bits | Created: ${key.created}</small>
                            </div>
                            <button class="btn btn-sm btn-danger" onclick="deleteKeyPair('${key.name}')">
                                <i class="bi bi-trash"></i> Delete
                            </button>
                        </div>
                    </div>
                `;
            });
            html += '</div>';

            container.innerHTML = html;
        }

        function updateKeyDropdowns(keys) {
            const publicKeySelects = ['encryptTextPublicKey', 'encryptFilePublicKey'];
            const privateKeySelects = ['decryptTextPrivateKey', 'decryptFilePrivateKey'];

            publicKeySelects.forEach(selectId => {
                const select = document.getElementById(selectId);
                if (select) {
                    select.innerHTML = '<option value="">-- Select Public Key --</option>';
                    keys.forEach(key => {
                        select.innerHTML += `<option value="${key.name}">${key.name} (${key.size} bits)</option>`;
                    });
                }
            });

            privateKeySelects.forEach(selectId => {
                const select = document.getElementById(selectId);
                if (select) {
                    select.innerHTML = '<option value="">-- Select Private Key --</option>';
                    keys.forEach(key => {
                        select.innerHTML += `<option value="${key.name}">${key.name} (${key.size} bits)</option>`;
                    });
                }
            });
        }

        function deleteKeyPair(keyName) {
            if (!confirm(`Delete key pair "${keyName}"?\nThis cannot be undone!`)) {
                return;
            }

            fetch('generate_keys.php', {
                    method: 'DELETE',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    body: 'keyname=' + encodeURIComponent(keyName)
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        showAlert('Key pair deleted successfully!', 'success');
                        loadKeyPairs();
                    } else {
                        showAlert('Failed to delete: ' + data.error, 'danger');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    showAlert('Error deleting key pair', 'danger');
                });
        }

        // ==========================================
        // ENCRYPT TEXT
        // ==========================================

        document.getElementById('encryptTextForm').addEventListener('submit', function(e) {
            e.preventDefault();

            const formData = new FormData(this);
            formData.append('action', 'encrypt_text');

            const submitBtn = this.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerHTML;
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Processing...';

            fetch('process.php', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = originalText;

                    if (data.success) {
                        document.getElementById('encryptTextResultMethod').textContent = data.method;
                        document.getElementById('encryptTextResultData').value = data.encrypted;
                        document.getElementById('encryptTextResultData').value = data.encrypted;
                        let infoHtml = `
                            <p class="mt-2 mb-0"><strong>Encryption Time:</strong> ${data.time_taken} detik</p>
                            <p class="mb-0"><strong>Original Size:</strong> ${data.original_size} bytes</p>
                            <p class="mb-0"><strong>Encrypted Size:</strong> ${data.encrypted_size} bytes</p>
                        `;
                        document.getElementById('encryptTextResultInfo').innerHTML = infoHtml;

                        if (data.encrypted_key) {
                            document.getElementById('encryptTextResultKey').value = data.encrypted_key;
                            document.getElementById('encryptTextResultKeyGroup').classList.remove('d-none');
                        } else {
                            document.getElementById('encryptTextResultKeyGroup').classList.add('d-none');
                        }

                        document.getElementById('encryptTextResult').classList.remove('d-none');
                        showAlert('Text encrypted successfully!', 'success');
                    } else {
                        showAlert('Encryption failed: ' + data.error, 'danger');
                    }
                })
                .catch(error => {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = originalText;
                    console.error('Error:', error);
                    showAlert('Error during encryption', 'danger');
                });
        });

        // ==========================================
        // DECRYPT TEXT
        // ==========================================

        document.getElementById('decryptTextForm').addEventListener('submit', function(e) {
            e.preventDefault();

            const formData = new FormData(this);
            formData.append('action', 'decrypt_text');

            const submitBtn = this.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerHTML;
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Processing...';

            fetch('process.php', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = originalText;

                    if (data.success) {
                        document.getElementById('decryptTextResultData').value = data.decrypted;
                        document.getElementById('decryptTextResult').classList.remove('d-none');
                        showAlert('Text decrypted successfully!', 'success');
                    } else {
                        showAlert('Decryption failed: ' + data.error, 'danger');
                    }
                })
                .catch(error => {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = originalText;
                    console.error('Error:', error);
                    showAlert('Error during decryption', 'danger');
                });
        });

        // ==========================================
        // ENCRYPT FILE
        // ==========================================

        document.getElementById('encryptFileForm').addEventListener('submit', function(e) {
            e.preventDefault();

            const formData = new FormData(this);
            formData.append('action', 'encrypt_file');

            const submitBtn = this.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerHTML;
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Encrypting...';

            fetch('process.php', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = originalText;

                    if (data.success) {
                        document.getElementById('encryptFileResultMethod').textContent = data.method;
                        document.getElementById('encryptFileResultName').textContent = data.original_name;
                        document.getElementById('encryptFileResultDownload').href = data.download_url;
                        document.getElementById('encryptFileResultOriginalSize').textContent = data.original_size_kb;
                        document.getElementById('encryptFileResultEncryptedSize').textContent = data.encrypted_size_kb;
                        document.getElementById('encryptFileResultTime').textContent = data.encryption_time_sec;
                        document.getElementById('encryptFileResult').classList.remove('d-none');
                        showAlert('File encrypted successfully!', 'success');
                    } else {
                        showAlert('Encryption failed: ' + data.error, 'danger');
                    }
                })
                .catch(error => {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = originalText;
                    console.error('Error:', error);
                    showAlert('Error during file encryption', 'danger');
                });
        });

        // ==========================================
        // CHECK METHOD (Auto-Detect)
        // ==========================================

        document.getElementById('checkMethodBtn').addEventListener('click', function() {
            const fileInput = document.querySelector('input[name="encrypted_file"]');

            if (!fileInput.files[0]) {
                showAlert('Please select a file first', 'warning');
                return;
            }

            const formData = new FormData();
            formData.append('encrypted_file', fileInput.files[0]);

            this.disabled = true;
            this.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Checking...';

            fetch('check_method.php', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    this.disabled = false;
                    this.innerHTML = '<i class="bi bi-search"></i> Auto-Detect Method';

                    if (data.success) {
                        document.getElementById('detectedMethod').textContent = data.method_display;
                        document.getElementById('detectedOriginalName').textContent = data.original_name;
                        document.getElementById('fileMethodInfo').classList.remove('d-none');

                        document.getElementById('decryptFileMethod').value = data.method;
                        toggleFieldVisibility(data.method, 'decryptFile');

                        showAlert('Method detected: ' + data.method_display, 'info');
                    } else {
                        showAlert('Detection failed: ' + data.error, 'danger');
                    }
                })
                .catch(error => {
                    this.disabled = false;
                    this.innerHTML = '<i class="bi bi-search"></i> Auto-Detect Method';
                    console.error('Error:', error);
                    showAlert('Error during method detection', 'danger');
                });
        });

        // ==========================================
        // DECRYPT FILE
        // ==========================================

        document.getElementById('decryptFileForm').addEventListener('submit', function(e) {
            e.preventDefault();

            const formData = new FormData(this);
            formData.append('action', 'decrypt_file');

            const submitBtn = this.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerHTML;
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Decrypting...';

            fetch('process.php', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = originalText;

                    if (data.success) {
                        document.getElementById('decryptFileResultName').textContent = data.original_name;
                        document.getElementById('decryptFileResultDownload').href = data.download_url;

                        if (data.can_preview && data.preview_url) {
                            const previewContent = document.getElementById('decryptFilePreviewContent');

                            if (data.preview_type === 'image') {
                                previewContent.innerHTML = `<img src="${data.preview_url}" class="img-fluid rounded" alt="Preview">`;
                            } else if (data.preview_type === 'pdf') {
                                previewContent.innerHTML = `<embed src="${data.preview_url}" type="application/pdf" width="100%" height="500px">`;
                            } else if (data.preview_type === 'text') {
                                previewContent.innerHTML = `<iframe src="${data.preview_url}" width="100%" height="300px" class="border rounded"></iframe>`;
                            }

                            document.getElementById('decryptFilePreview').classList.remove('d-none');
                        } else {
                            document.getElementById('decryptFilePreview').classList.add('d-none');
                        }

                        document.getElementById('decryptFileResult').classList.remove('d-none');
                        showAlert('File decrypted successfully!', 'success');
                    } else {
                        showAlert('Decryption failed: ' + data.error, 'danger');
                    }
                })
                .catch(error => {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = originalText;
                    console.error('Error:', error);
                    showAlert('Error during file decryption', 'danger');
                });
        });

        // ==========================================
        // GENERATE KEY PAIR
        // ==========================================

        document.getElementById('generateKeyForm').addEventListener('submit', function(e) {
            e.preventDefault();

            const formData = new FormData(this);

            const submitBtn = this.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerHTML;
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Generating... (30-60s)';

            fetch('generate_keys.php', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = originalText;

                    if (data.success) {
                        document.getElementById('keyGenMethod').textContent = data.method;
                        document.getElementById('keyGenName').textContent = data.key_name;
                        document.getElementById('keyGenSize').textContent = data.key_size;
                        document.getElementById('generateKeyResult').classList.remove('d-none');

                        showAlert('Key pair generated successfully!', 'success');
                        loadKeyPairs();
                        this.reset();
                    } else {
                        showAlert('Key generation failed: ' + data.error, 'danger');
                    }
                })
                .catch(error => {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = originalText;
                    console.error('Error:', error);
                    showAlert('Error during key generation', 'danger');
                });
        });

        // ==========================================
        // EVENT LISTENERS FOR METHOD CHANGES
        // ==========================================

        document.getElementById('encryptTextMethod').addEventListener('change', function() {
            toggleFieldVisibility(this.value, 'encryptText');
        });

        document.getElementById('encryptFileMethod').addEventListener('change', function() {
            toggleFieldVisibility(this.value, 'encryptFile');
        });

        document.getElementById('decryptTextMethod').addEventListener('change', function() {
            toggleFieldVisibility(this.value, 'decryptText');
        });

        document.getElementById('decryptFileMethod').addEventListener('change', function() {
            toggleFieldVisibility(this.value, 'decryptFile');
        });

        // ==========================================
        // INITIALIZATION
        // ==========================================

        document.addEventListener('DOMContentLoaded', function() {
            loadKeyPairs();
            toggleFieldVisibility('aes-gcm', 'encryptText');
            toggleFieldVisibility('aes-gcm', 'encryptFile');
            toggleFieldVisibility('aes-gcm', 'decryptText');
            toggleFieldVisibility('aes-gcm', 'decryptFile');
        });
    </script>
</body>

</html>