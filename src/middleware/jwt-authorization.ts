/**
 * Copyright 2023 Kapeta Inc.
 * SPDX-License-Identifier: MIT
 */

import {Request, Response, NextFunction} from 'express';
import {JWTAuthHandler} from "../JWTAuthHandler";
import {AuthError} from "../types";
import {RequestHandler} from "express-serve-static-core";

interface JWTAuthOpts {
    required?: boolean;
    handler: JWTAuthHandler;
}

export const jwtAuthorization = (opts: JWTAuthOpts):RequestHandler => {
    return (req: Request, res: Response, next: NextFunction) => {

        if (!req.authHandler) {
            req.authHandler = opts.handler;
        }
        req.isAuthenticated = () => Boolean(req.auth);

        const authHeader = req.header('Authorization');
        if (!authHeader || authHeader.toLowerCase().trim().startsWith('bearer ')) {
            if (opts.required) {
                return next(new AuthError('Authorization is required', 401));
            }
            // Ignore non-authed request - we are just here to verify the token if it exists
            return next();
        }

        const token = authHeader.split(' ')[1];
        if (!token) {
            return next(new AuthError('Authorization is required', 401));
        }

        req.authHandler.verifyToken(token).then((jwt) => {
            req.auth = jwt;
            next();
        }).catch((err) => {
            next(new AuthError(`Invalid token: ${err.message}`, 401));
        });

    }
};