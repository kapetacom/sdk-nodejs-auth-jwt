/**
 * Copyright 2023 Kapeta Inc.
 * SPDX-License-Identifier: MIT
 */
import { JwksClient } from 'jwks-rsa';
import { Algorithm } from 'jsonwebtoken';
import { JWKS, JWTKeyPair, JWTKeyStore, KeyWithAlgorithm } from './types';

export class JWTKeyHandlerExternal implements JWTKeyStore {
    private readonly jwksClient: JwksClient;
    private readonly _issuer: string;
    private readonly _audience: string | string[];

    constructor(jwksUri: string, issuer: string, audience: string | string[]) {
        this._issuer = issuer;
        this._audience = audience;

        console.log(
            'Using external keystore with issuer "%s" and audience "%s"\n\t JWKS: %s',
            issuer,
            audience,
            jwksUri
        );

        this.jwksClient = new JwksClient({
            jwksUri: jwksUri,
            cache: true,
            cacheMaxAge: 3600,
        });
    }

    get audience(): string | string[] {
        return this._audience;
    }

    async getPublicKey(kid: string): Promise<KeyWithAlgorithm> {
        const key = await this.jwksClient.getSigningKey(kid);
        if (!key) {
            throw new Error('Key not found: ' + kid);
        }

        return {
            alg: key.alg as Algorithm,
            value: key.getPublicKey(),
        };
    }

    get issuer(): string {
        return this._issuer;
    }

    canSign(): boolean {
        return false;
    }

    async getKeyPair(): Promise<JWTKeyPair> {
        throw new Error('External key handler does not have access to private key');
    }

    public toJWKS(): JWKS {
        throw new Error('External key handler does not have access to private key');
    }
}
