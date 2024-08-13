import { bech32 } from "@scure/base";
import { hmac } from "@noble/hashes/hmac";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { x25519 } from "@noble/curves/ed25519";
import { randomBytes } from "@noble/hashes/utils";
import { scryptUnwrap, scryptWrap, x25519Unwrap, x25519Wrap } from "./recipients.js";
import { encodeHeader, encodeHeaderNoMAC, parseHeader } from "./format.js";
import { decryptSTREAM, encryptSTREAM } from "./stream.js";
export function generateIdentity() {
    const scalar = randomBytes(32);
    return bech32.encode("AGE-SECRET-KEY-", bech32.toWords(scalar)).toUpperCase();
}
export function identityToRecipient(identity) {
    const res = bech32.decodeToBytes(identity);
    if (!identity.startsWith("AGE-SECRET-KEY-1") ||
        res.prefix.toUpperCase() !== "AGE-SECRET-KEY-" ||
        res.bytes.length !== 32)
        throw Error("invalid identity");
    const recipient = x25519.scalarMultBase(res.bytes);
    return bech32.encode("age", bech32.toWords(recipient));
}
export class Encrypter {
    constructor() {
        this.passphrase = null;
        this.scryptWorkFactor = 18;
        this.recipients = [];
    }
    setPassphrase(s) {
        if (this.passphrase !== null)
            throw new Error("can encrypt to at most one passphrase");
        if (this.recipients.length !== 0)
            throw new Error("can't encrypt to both recipients and passphrases");
        this.passphrase = s;
    }
    setScryptWorkFactor(logN) {
        this.scryptWorkFactor = logN;
    }
    addRecipient(s) {
        if (this.passphrase !== null)
            throw new Error("can't encrypt to both recipients and passphrases");
        const res = bech32.decodeToBytes(s);
        if (!s.startsWith("age1") ||
            res.prefix.toLowerCase() !== "age" ||
            res.bytes.length !== 32)
            throw Error("invalid recipient");
        this.recipients.push(res.bytes);
    }
    encrypt(file) {
        if (typeof file === "string") {
            file = new TextEncoder().encode(file);
        }
        const fileKey = randomBytes(16);
        const stanzas = [];
        for (const recipient of this.recipients) {
            stanzas.push(x25519Wrap(fileKey, recipient));
        }
        if (this.passphrase !== null) {
            stanzas.push(scryptWrap(fileKey, this.passphrase, this.scryptWorkFactor));
        }
        const hmacKey = hkdf(sha256, fileKey, undefined, "header", 32);
        const mac = hmac(sha256, hmacKey, encodeHeaderNoMAC(stanzas));
        const header = encodeHeader(stanzas, mac);
        const nonce = randomBytes(16);
        const streamKey = hkdf(sha256, fileKey, nonce, "payload", 32);
        const payload = encryptSTREAM(streamKey, file);
        const out = new Uint8Array(header.length + nonce.length + payload.length);
        out.set(header);
        out.set(nonce, header.length);
        out.set(payload, header.length + nonce.length);
        return out;
    }
}
export class Decrypter {
    constructor() {
        this.passphrases = [];
        this.identities = [];
    }
    addPassphrase(s) {
        this.passphrases.push(s);
    }
    addIdentity(s) {
        const res = bech32.decodeToBytes(s);
        if (!s.startsWith("AGE-SECRET-KEY-1") ||
            res.prefix.toUpperCase() !== "AGE-SECRET-KEY-" ||
            res.bytes.length !== 32)
            throw Error("invalid identity");
        this.identities.push({
            identity: res.bytes,
            recipient: x25519.scalarMultBase(res.bytes),
        });
    }
    decrypt(file, outputFormat) {
        const h = parseHeader(file);
        const fileKey = this.unwrapFileKey(h.recipients);
        if (fileKey === null) {
            throw Error("no identity matched any of the file's recipients");
        }
        const hmacKey = hkdf(sha256, fileKey, undefined, "header", 32);
        const mac = hmac(sha256, hmacKey, h.headerNoMAC);
        if (!compareBytes(h.MAC, mac)) {
            throw Error("invalid header HMAC");
        }
        const nonce = h.rest.subarray(0, 16);
        const streamKey = hkdf(sha256, fileKey, nonce, "payload", 32);
        const payload = h.rest.subarray(16);
        const out = decryptSTREAM(streamKey, payload);
        if (outputFormat === "text")
            return new TextDecoder().decode(out);
        return out;
    }
    unwrapFileKey(recipients) {
        for (const s of recipients) {
            // Ideally this should be implemented by passing all stanzas to the scrypt
            // identity implementation, and letting it throw the error. In practice,
            // this is a very simple implementation with no public identity interface.
            if (s.args.length > 0 && s.args[0] === "scrypt" && recipients.length !== 1) {
                throw Error("scrypt recipient is not the only one in the header");
            }
            for (const p of this.passphrases) {
                const k = scryptUnwrap(s, p);
                if (k !== null) {
                    return k;
                }
            }
            for (const i of this.identities) {
                const k = x25519Unwrap(s, i);
                if (k !== null) {
                    return k;
                }
            }
        }
        return null;
    }
}
function compareBytes(a, b) {
    if (a.length !== b.length) {
        return false;
    }
    let acc = 0;
    for (let i = 0; i < a.length; i++) {
        acc |= a[i] ^ b[i];
    }
    return acc === 0;
}
