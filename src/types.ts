import { Jwt } from 'jsonwebtoken';
import { JWTAuthHandler } from './JWTAuthHandler';

declare global {
    export namespace Express {
        export interface Request {
            auth?: Jwt;
            authHandler?: JWTAuthHandler;
            isAuthenticated: () => boolean;
        }
    }
}

export const PORT_TYPE = 'http';
export const PATH_KAPETA_AUTHENTICATION = '/.kapeta/authentication.json';
export const PATH_WELL_KNOWN_JWKS = '/.well-known/jwks.json';
export type { Jwt, JwtPayload, JwtHeader, Algorithm } from 'jsonwebtoken';

export class AuthError extends Error {
    public readonly statusCode: number;

    constructor(message: string, statusCode: number) {
        super(message);
        this.statusCode = statusCode;
    }
}

export interface KapetaAuthenticationMetadata {
    type: 'jwt';
    jwks: string;
    issuer: string;
    audience: string | string[];
}
