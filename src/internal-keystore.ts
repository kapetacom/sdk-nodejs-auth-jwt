import {JWTKeyStore, JWTKeyStoreInternal} from "./keystores";
import {JWK} from "node-jose";

export const createInternalKeyStore = (keyStore:JWK.KeyStore, issuer: string, audience: string|string[]):JWTKeyStore => {
    return new JWTKeyStoreInternal(keyStore, issuer, audience);
}