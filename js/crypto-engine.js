// ===============================
// 🔐 CryptoEngine - JavaScript
// ===============================

// Utility: ubah password menjadi key 256-bit untuk AES
async function deriveKeyFromPassword(password) {
	const enc = new TextEncoder();
	const keyMaterial = await crypto.subtle.digest(
		"SHA-256",
		enc.encode(password)
	); // 32-byte hash
	return crypto.subtle.importKey(
		"raw",
		keyMaterial,
		{ name: "AES-GCM" },
		false,
		["encrypt", "decrypt"]
	);
}

class CryptoEngine {
	// ===============================
	// 🔸 ENCRYPT
	// ===============================
	static async encrypt(plaintext, method, key) {
		switch (method) {
			case "base64":
				return btoa(plaintext);
			case "hex":
				return Array.from(new TextEncoder().encode(plaintext))
					.map((b) => b.toString(16).padStart(2, "0"))
					.join("");
			case "sha256":
				return CryptoJS.SHA256(plaintext).toString();
			case "sha512":
				return CryptoJS.SHA512(plaintext).toString();
			case "sha3-256":
				return CryptoJS.SHA3(plaintext, { outputLength: 256 }).toString();
			case "aes-cbc":
				return CryptoJS.AES.encrypt(plaintext, key).toString();
			case "aes-gcm":
				return await this.encryptAESGCM(plaintext, key);
			default:
				throw new Error("Unknown method: " + method);
		}
	}

	// ===============================
	// 🔸 DECRYPT
	// ===============================
	static async decrypt(ciphertext, method, key) {
		switch (method) {
			case "aes-cbc":
				return CryptoJS.AES.decrypt(ciphertext, key).toString(
					CryptoJS.enc.Utf8
				);
			case "aes-gcm":
				return await this.decryptAESGCM(ciphertext, key);
			default:
				throw new Error("Unknown method for decryption: " + method);
		}
	}

	// ===============================
	// 🔹 AES-GCM TEXT ENCRYPTION
	// ===============================
	static async encryptAESGCM(plaintext, key) {
		const enc = new TextEncoder();
		const iv = crypto.getRandomValues(new Uint8Array(12));
		const cryptoKey = await deriveKeyFromPassword(key);

		const ciphertext = await crypto.subtle.encrypt(
			{ name: "AES-GCM", iv },
			cryptoKey,
			enc.encode(plaintext)
		);

		return btoa(
			JSON.stringify({
				iv: Array.from(iv),
				data: Array.from(new Uint8Array(ciphertext)),
			})
		);
	}

	// ===============================
	// 🔹 AES-GCM TEXT DECRYPTION
	// ===============================
	static async decryptAESGCM(ciphertext, key) {
		const dec = new TextDecoder();
		const json = JSON.parse(atob(ciphertext));
		const iv = new Uint8Array(json.iv);
		const data = new Uint8Array(json.data);

		const cryptoKey = await deriveKeyFromPassword(key);
		const decrypted = await crypto.subtle.decrypt(
			{ name: "AES-GCM", iv },
			cryptoKey,
			data
		);

		return dec.decode(decrypted);
	}

	// ===============================
	// 🔹 AES-GCM FILE ENCRYPTION
	// ===============================
	static async encryptFile(file, method, key) {
		const arrayBuffer = await file.arrayBuffer();

		if (method === "aes-gcm") {
			const iv = crypto.getRandomValues(new Uint8Array(12));
			const cryptoKey = await deriveKeyFromPassword(key);

			const encrypted = await crypto.subtle.encrypt(
				{ name: "AES-GCM", iv },
				cryptoKey,
				arrayBuffer
			);

			// Simpan IV di depan ciphertext supaya bisa didekripsi nanti
			const combined = new Uint8Array(iv.byteLength + encrypted.byteLength);
			combined.set(iv, 0);
			combined.set(new Uint8Array(encrypted), iv.byteLength);

			return combined;
		}

		throw new Error("Unsupported file encryption method: " + method);
	}

	// ===============================
	// 🔹 AES-GCM FILE DECRYPTION
	// ===============================
	static async decryptFile(encryptedArrayBuffer, key) {
		const data = new Uint8Array(encryptedArrayBuffer);
		const iv = data.slice(0, 12); // Ambil IV dari awal file
		const ciphertext = data.slice(12);

		const cryptoKey = await deriveKeyFromPassword(key);

		const decrypted = await crypto.subtle.decrypt(
			{ name: "AES-GCM", iv },
			cryptoKey,
			ciphertext
		);

		return new Blob([decrypted]); // Hasil dalam bentuk Blob
	}
}
