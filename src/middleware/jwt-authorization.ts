/**
 * Copyright 2023 Kapeta Inc.
 * SPDX-License-Identifier: MIT
 */

import { Request, Response, NextFunction } from 'express';
import { JWTAuthHandler } from '../JWTAuthHandler';
import { AuthError } from '../types';
import { RequestHandler } from 'express-serve-static-core';
import { JWTKeyStore } from '../keystores';
import { Jwt } from 'jsonwebtoken';
import { AsyncLocalStorage } from 'async_hooks';

export type TokenResolver = (req: Request) => string;

interface JWTAuthOpts {
    required?: boolean;
    keyStores: JWTKeyStore[];
    tokenResolver?: TokenResolver;
}

export interface JWTToken {
    jwt: Jwt;
    token: string;
}

const thisGlobal = global as any;
const LOCAL_STORAGE: AsyncLocalStorage<JWTToken> =
    thisGlobal.JWT_AUTH_LOCAL_STORAGE ?? (thisGlobal.JWT_AUTH_LOCAL_STORAGE = new AsyncLocalStorage());

export const getJWTToken = () => LOCAL_STORAGE.getStore();

const resolveFromAuthorizationHeader: TokenResolver = (req: Request): string => {
    const authHeader = req.header('Authorization');
    if (!authHeader || !authHeader.toLowerCase().trim().startsWith('bearer ')) {
        throw new Error('Authorization header was missing or invalid');
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
        throw new Error('Authorization header was malformed');
    }
    return token;
};

export const jwtAuthorization = (opts: JWTAuthOpts): RequestHandler => {
    if (!opts.keyStores || opts.keyStores.length === 0) {
        throw new Error('JWT Authorization middleware requires at least one key store');
    }
    const authHandler = new JWTAuthHandler(...opts.keyStores);

    const tokenResolver = opts.tokenResolver ?? resolveFromAuthorizationHeader;

    console.log('JWT Authorization middleware initialized with %s keystore(s)', opts.keyStores.length);

    return (req: Request, res: Response, next: NextFunction) => {
        req.authHandler = authHandler;
        req.isAuthenticated = () => Boolean(req.auth);

        let token: string;
        try {
            token = tokenResolver(req);
        } catch (e: any) {
            if (opts.required) {
                return next(new AuthError(e.message, 401));
            }
            // Ignore non-authed request - we are just here to verify the token if it exists
            return next();
        }

        authHandler
            .verifyToken(token)
            .then((jwt) => {
                req.auth = jwt;
                // Store the token in the async local storage so that it can be accessed by other middleware and clients
                LOCAL_STORAGE.run({ jwt, token }, next);
            })
            .catch((err) => {
                next(new AuthError(`Invalid token: ${err.message}`, 401));
            });
    };
};
