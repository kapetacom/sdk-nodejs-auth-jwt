/**
 * Copyright 2023 Kapeta Inc.
 * SPDX-License-Identifier: MIT
 */
import { Router } from 'express';
import { KapetaAuthenticationMetadata, PATH_KAPETA_AUTHENTICATION, PATH_WELL_KNOWN_JWKS } from '../types';
import { JWTKeyStore } from '../keystores';

export const jwksRoutes = (keyStore: JWTKeyStore): Router => {
    const router = Router();

    console.log('Publishing JWKS on %s', PATH_WELL_KNOWN_JWKS);
    router.get(PATH_WELL_KNOWN_JWKS, (req, res) => {
        res.json(keyStore.toJWKS());
    });

    console.log('Publishing Kapeta authentication metadata on %s', PATH_KAPETA_AUTHENTICATION);
    router.get(PATH_KAPETA_AUTHENTICATION, (req, res) => {
        const metadata: KapetaAuthenticationMetadata = {
            type: 'jwt',
            jwks: PATH_WELL_KNOWN_JWKS,
            issuer: keyStore.issuer,
            audience: keyStore.audience,
        };
        res.json(metadata);
    });

    return router;
};
