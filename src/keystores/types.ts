/**
 * Copyright 2023 Kapeta Inc.
 * SPDX-License-Identifier: MIT
 */
import { Algorithm } from 'jsonwebtoken';

export interface JWTKeyPair {
    kid: string;
    alg: Algorithm;
    kty: string;
    use: string;
    publicKey: string;
    privateKey: string;
}

export interface KeyWithAlgorithm {
    alg: Algorithm;
    value: string;
}

export interface JWTKeyStore {
    getPublicKey(kid: string): Promise<KeyWithAlgorithm>;
    getKeyPair(): Promise<JWTKeyPair>;
    canSign(): boolean;
    get issuer(): string;
    get audience(): string | string[];
    toJWKS(): JWKS;
}

export interface JWK {
    alg: Algorithm;
    kty: string;
    use: string;
    x5c: string[];
    n: string;
    e: string;
    kid: string;
    x5t: string;
    [key: string]: any;
}

export interface JWKS {
    keys: JWK[];
}
