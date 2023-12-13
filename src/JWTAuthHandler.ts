/**
 * Copyright 2023 Kapeta Inc.
 * SPDX-License-Identifier: MIT
 */
import jwt, {DecodeOptions, Jwt, JwtPayload, SignOptions, VerifyOptions} from 'jsonwebtoken';
import {JWTKeyStore} from "./keystores";

export class JWTAuthHandler {
    public readonly keyStores:JWTKeyStore[];



    constructor(...keyStores:JWTKeyStore[]) {
        this.keyStores = keyStores;
    }

    private decodeToken(token: string, options?: DecodeOptions):Jwt | null {
        return jwt.decode(token, {
            ...options,
            complete: true,
        });
    }

    public async verifyToken(token: string, options?: VerifyOptions):Promise<Jwt> {
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

            const issuer = jwtToken.payload.iss;

            const keyStore = this.keyStores.find((keyStore) => keyStore.issuer === issuer);

            if (!keyStore) {
                reject(new Error('Invalid token: Invalid issuer'));
                return;
            }

            const publicKey = await keyStore.getPublicKey(jwtToken.header.kid);

            jwt.verify(token, publicKey.value, {
                issuer: keyStore.issuer,
                audience: keyStore.audience,
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

    public async createToken(payload: Omit<JwtPayload,'iss'|'aud'|'iat'> & {sub:string}, options?: SignOptions):Promise<string> {
        return new Promise(async (resolve, reject) => {
            const keyStore = this.keyStores.find(keyStore => {
                if (!keyStore.canSign()) {
                    return false;
                }
                if (!options?.issuer) {
                    return true;
                }
                return keyStore.issuer === options?.issuer;
            });

            if (!keyStore) {
                reject(new Error('Missing key store or invalid issuer'));
                return;
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
            });
        });
    }
}