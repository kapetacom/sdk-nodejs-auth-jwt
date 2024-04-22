/**
 * Copyright 2023 Kapeta Inc.
 * SPDX-License-Identifier: MIT
 */
import jwt, { DecodeOptions, Jwt, JwtPayload, SignOptions, VerifyOptions } from 'jsonwebtoken';
import { JWTKeyStore } from './keystores';

export class JWTAuthHandler {
    public readonly keyStores: JWTKeyStore[];

    constructor(...keyStores: JWTKeyStore[]) {
        this.keyStores = keyStores;
    }

    private decodeToken(token: string, options?: DecodeOptions): Jwt | null {
        return jwt.decode(token, {
            ...options,
            complete: true,
        });
    }

    public async verifyToken(token: string, options?: VerifyOptions): Promise<Jwt> {
        const jwtToken = this.decodeToken(token);

        if (!jwtToken) {
            throw new Error('Invalid token');
        }

        if (!jwtToken.header.kid) {
            throw new Error('Invalid token: Missing kid claim');
        }

        if (typeof jwtToken.payload === 'string') {
            throw new Error('Invalid token: Invalid payload');
        }

        const issuer = jwtToken.payload.iss;

        const keyStore = this.keyStores.find((keyStore) => keyStore.issuer === issuer);

        if (!keyStore) {
            throw new Error('Invalid token: Invalid issuer');
        }

        const publicKey = await keyStore.getPublicKey(jwtToken.header.kid);

        return new Promise((resolve, reject) =>
            jwt.verify(
                token,
                publicKey.value,
                {
                    issuer: keyStore.issuer,
                    audience: keyStore.audience,
                    algorithms: publicKey.alg ? [publicKey.alg] : undefined,
                    ...options,
                    complete: true,
                },
                (err, decoded) => {
                    if (err) {
                        reject(err);
                        return;
                    }
                    if (!decoded) {
                        reject(new Error('Invalid token'));
                        return;
                    }
                    resolve(decoded);
                }
            )
        );
    }

    public async createToken(
        payload: Omit<JwtPayload, 'iss' | 'aud' | 'iat'> & { sub: string },
        options?: SignOptions
    ): Promise<string> {
        const keyStore = this.keyStores.find((keyStore) => {
            if (!keyStore.canSign()) {
                return false;
            }
            if (!options?.issuer) {
                return true;
            }
            return keyStore.issuer === options?.issuer;
        });

        if (!keyStore) {
            throw new Error('Missing key store or invalid issuer');
        }

        const keyPair = await keyStore.getKeyPair();
        const signOptions = {
            issuer: keyStore.issuer,
            audience: keyStore.audience,
            algorithm: keyPair.alg,
            keyid: keyPair.kid,
            encoding: 'utf8',
            allowInsecureKeySizes: false,
            allowInvalidAsymmetricKeyTypes: false,
            ...options,
        };

        if (payload.jti) {
            delete signOptions.jwtid;
        }

        if (payload.nbf) {
            delete signOptions.notBefore;
        }

        if (payload.exp) {
            delete signOptions.expiresIn;
        }

        return new Promise((resolve, reject) =>
            jwt.sign(payload, keyPair.privateKey, signOptions, (err, token) => {
                if (err) {
                    reject(err);
                    return;
                }
                if (!token) {
                    reject(new Error('Invalid token'));
                    return;
                }
                resolve(token);
            })
        );
    }
}
