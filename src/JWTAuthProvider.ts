import {JWTKeyStoreInternal, JWTKeyStore} from "./keystores";
import {JWK} from "node-jose";
import {jwksRoutes} from "./middleware/jwks-routes";
import {Router} from "express";

export const createJWTAuthProvider = (keyStore:JWK.KeyStore, issuer: string, audience: string|string[]):Router => {
    const internalStore = new JWTKeyStoreInternal(keyStore, issuer, audience);

    return jwksRoutes(internalStore);
}