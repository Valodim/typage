export declare function generateIdentity(): Promise<string>;
export declare function identityToRecipient(identity: string | CryptoKey): Promise<string>;
export declare class Encrypter {
    private passphrase;
    private scryptWorkFactor;
    private recipients;
    setPassphrase(s: string): void;
    setScryptWorkFactor(logN: number): void;
    addRecipient(s: string): void;
    encrypt(file: Uint8Array | string): Promise<Uint8Array>;
}
export declare class Decrypter {
    private passphrases;
    private identities;
    addPassphrase(s: string): void;
    addIdentity(s: string | CryptoKey): void;
    decrypt(file: Uint8Array, outputFormat?: "uint8array"): Promise<Uint8Array>;
    decrypt(file: Uint8Array, outputFormat: "text"): Promise<string>;
    private unwrapFileKey;
}
