const input = document.getElementById("inputText");
const result = document.getElementById("result");
const passphraseInput = document.getElementById("passphrase");

function bytesToBase64(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

function base64ToBytes(value) {
    const binary = atob(value);
    return Uint8Array.from(binary, character => character.charCodeAt(0));
}

function getPassphrase() {
    const passphrase = passphraseInput.value;
    if (passphrase.length < 8) {
        throw new Error("Use a passphrase of at least 8 characters.");
    }
    return passphrase;
}

async function deriveKey(passphrase, salt) {
    const material = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(passphrase),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: 250000, hash: "SHA-256" },
        material,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

async function encryptText() {
    try {
        if (!input.value) throw new Error("Please enter text to encrypt.");
        if (!window.crypto || !crypto.subtle) throw new Error("Secure Web Crypto is unavailable. Use HTTPS or localhost.");
        const passphrase = getPassphrase();
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await deriveKey(passphrase, salt);
        const encrypted = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            key,
            new TextEncoder().encode(input.value)
        );

        const envelope = {
            version: 1,
            algorithm: "AES-GCM",
            kdf: "PBKDF2-SHA-256",
            iterations: 250000,
            salt: bytesToBase64(salt),
            iv: bytesToBase64(iv),
            ciphertext: bytesToBase64(new Uint8Array(encrypted))
        };
        result.textContent = "Encrypted (save this output): " + bytesToBase64(new TextEncoder().encode(JSON.stringify(envelope)));
    } catch (error) {
        result.textContent = error instanceof Error ? error.message : "Encryption failed.";
    }
}

async function decryptText() {
    try {
        if (!input.value.trim()) throw new Error("Paste the encrypted output into the text field.");
        if (!window.crypto || !crypto.subtle) throw new Error("Secure Web Crypto is unavailable. Use HTTPS or localhost.");
        const passphrase = getPassphrase();
        let envelope;
        try {
            envelope = JSON.parse(new TextDecoder().decode(base64ToBytes(input.value.trim())));
        } catch {
            throw new Error("Invalid encrypted data format.");
        }

        if (
            !envelope ||
            envelope.version !== 1 ||
            envelope.algorithm !== "AES-GCM" ||
            envelope.kdf !== "PBKDF2-SHA-256" ||
            envelope.iterations !== 250000 ||
            typeof envelope.salt !== "string" ||
            typeof envelope.iv !== "string" ||
            typeof envelope.ciphertext !== "string"
        ) {
            throw new Error("Unsupported or malformed encrypted data.");
        }

        const salt = base64ToBytes(envelope.salt);
        const iv = base64ToBytes(envelope.iv);
        const ciphertext = base64ToBytes(envelope.ciphertext);
        if (salt.length !== 16 || iv.length !== 12 || ciphertext.length < 16) {
            throw new Error("Encrypted data is incomplete or malformed.");
        }

        const key = await deriveKey(passphrase, salt);
        const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
        result.textContent = "Decrypted: " + new TextDecoder("utf-8", { fatal: true }).decode(decrypted);
    } catch (error) {
        result.textContent = error instanceof Error
            ? (error.name === "OperationError" ? "Decryption failed. The passphrase may be wrong or the data was modified." : error.message)
            : "Decryption failed.";
    }
}

function clearText() {
    input.value = "";
    passphraseInput.value = "";
    result.textContent = "";
}
