/**
 * Copyright 2023 Kapeta Inc.
 * SPDX-License-Identifier: MIT
 */
import jwt, {DecodeOptions, Jwt, JwtPayload, SignOptions, VerifyOptions} from 'jsonwebtoken';
import {JWTKeyStore} from "./keystores";

export class JWTAuthHandler {
    public readonly keyStore:JWTKeyStore;

    constructor(keyStore:JWTKeyStore) {
        this.keyStore = keyStore;
    }

    private decodeToken(token: string, options?: DecodeOptions):Jwt | null {
        return jwt.decode(token, {
            ...options,
            complete: true,
        });
    }

    async verifyToken(token: string, options?: VerifyOptions):Promise<Jwt> {
        return new Promise(async (resolve, reject) => {

            const jwtToken = this.decodeToken(token);

            if (!jwtToken) {
                reject(new Error('Invalid token'));
                return;
            }

            if (!jwtToken.header.kid) {
                reject(new Error('Invalid token: Missing kid claim'));
                return;
            }


            if (typeof jwtToken.payload === 'string') {
                reject(new Error('Invalid token: Invalid payload'));
                return;
            }

            if (jwtToken.payload.iss !== this.keyStore.issuer) {
                reject(new Error('Invalid token: Invalid issuer'));
                return;
            }

            const publicKey = await this.keyStore.getPublicKey(jwtToken.header.kid);

            jwt.verify(token, publicKey.value, {
                issuer: this.keyStore.issuer,
                audience: this.keyStore.audience,
                algorithms: [publicKey.alg],
                ...options,
                complete: true,
            }, (err, decoded) => {
                if (err) {
                    reject(err);
                    return;
                }
                if (!decoded) {
                    reject(new Error('Invalid token'));
                    return;
                }
                resolve(decoded);
            });
        })
    }

    async createToken(payload: Omit<JwtPayload,'iss'|'aud'>, options?: SignOptions):Promise<string> {
        return new Promise(async (resolve, reject) => {

            const keyPair = await this.keyStore.getKeyPair();
            jwt.sign(payload, keyPair.privateKey, {
                issuer: this.keyStore.issuer,
                audience: this.keyStore.audience,
                algorithm: keyPair.alg,
                keyid: keyPair.kid,
                subject: payload.sub,
                jwtid: payload.jti,
                expiresIn: payload.exp,
                encoding: 'utf8',
                notBefore: payload.nbf,
                allowInsecureKeySizes: false,
                allowInvalidAsymmetricKeyTypes: false,
                ...options,
            }, (err, token) => {
                if (err) {
                    reject(err);
                    return;
                }
                if (!token) {
                    reject(new Error('Invalid token'));
                    return;
                }
                resolve(token);
            });
        });
    }
}