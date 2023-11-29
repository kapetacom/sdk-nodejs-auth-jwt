/**
 * Copyright 2023 Kapeta Inc.
 * SPDX-License-Identifier: MIT
 */
import {JWK} from "node-jose";
import {Algorithm} from "jsonwebtoken";
import FSExtra from "fs-extra";
import {JWKS, JWTKeyPair, JWTKeyStore, KeyWithAlgorithm} from "./types";

export async function ensureFileKeystore(filename:string) {
    try {
        const fileStat = await FSExtra.stat(filename);
        if (fileStat.isFile()) {
            const content = await FSExtra.readFile(filename);
            return await JWK.asKeyStore(content.toString());
        }
    } catch (e) {
        // ignore
    }

    const keyStore = await createInMemoryKeystore();
    await FSExtra.writeFile(filename, JSON.stringify(keyStore.toJSON(true)));
    return keyStore
}

export async function createInMemoryKeystore() {
    const keyStore = JWK.createKeyStore();
    await keyStore.generate('RSA', 2048, {alg: 'RS256', use: 'sig' });
    return keyStore;
}


export class JWTKeyStoreInternal implements JWTKeyStore {
    private readonly _issuer:string;
    private readonly _audience:string|string[];
    private readonly keyStore:JWK.KeyStore;

    constructor(keyStore: JWK.KeyStore, issuer:string, audience:string|string[]) {
        this.keyStore = keyStore;
        this._issuer = issuer;
        this._audience = audience;

        console.log('Using internal keystore with issuer "%s" and audience "%s"', issuer, audience);
    }

    get audience(): string | string[] {
        return this._audience;
    }

    get issuer(): string {
        return this._issuer;
    }

    canSign(): boolean {
        return true;
    }

    async getPublicKey(kid: string): Promise<KeyWithAlgorithm> {
        const key = this.keyStore.get({kid});
        if (!key) {
            throw new Error('Key not found: ' + kid);
        }

        return {
            alg: key.alg as Algorithm,
            value: key.toPEM(false),
        };
    }

    async getKeyPair():Promise<JWTKeyPair> {
        const keys = this.keyStore.all({use: 'sig'});
        if (!keys || keys.length === 0) {
            throw new Error('Not keys found');
        }
        const key = keys[0];

        return {
            alg: key.alg as Algorithm,
            kid: key.kid,
            kty: key.kty,
            use: key.use,
            privateKey: key.toPEM(true),
            publicKey: key.toPEM(false),
        }
    }

    public toJWKS(): JWKS {
        return this.keyStore.toJSON(false) as JWKS;
    }
}