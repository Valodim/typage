export declare function generateIdentity(): string;
export declare function identityToRecipient(identity: string): string;
export declare class Encrypter {
    private passphrase;
    private scryptWorkFactor;
    private recipients;
    setPassphrase(s: string): void;
    setScryptWorkFactor(logN: number): void;
    addRecipient(s: string): void;
    encrypt(file: Uint8Array | string): Uint8Array;
}
export declare class Decrypter {
    private passphrases;
    private identities;
    addPassphrase(s: string): void;
    addIdentity(s: string): void;
    decrypt(file: Uint8Array, outputFormat?: "uint8array"): Uint8Array;
    decrypt(file: Uint8Array, outputFormat: "text"): string;
    private unwrapFileKey;
}
