import Config, {ConfigProvider} from "@kapeta/sdk-config";
import {JWTKeyHandlerExternal, JWTKeyStore} from "./keystores";
import {KapetaAuthenticationMetadata, PATH_KAPETA_AUTHENTICATION, PORT_TYPE} from "./types";
import {jwtAuthorization} from "./middleware/jwt-authorization";
import {JWTAuthHandler} from "./JWTAuthHandler";
import { createDelayedRequestHandler } from "@kapeta/sdk-server";
import {RequestHandler} from "express-serve-static-core";

export const createJWTAuthConsumer = (resourceName: string):RequestHandler => {
    return new JWTAuthConsumer(resourceName).toExpress();
}

class ResolvablePromise<T> extends Promise<T> {
    private _reject?: (err:any) => void;
    private _resolve?: (value: T) => void;
    private done: boolean = false;
    public resolved?: T;
    public error?: T;

    constructor() {
        super((resolve, reject) => {
            this._resolve = resolve;
            this._reject = reject;
        });

        this.then((value) => {
            this.resolved = value;
            this.done = true;
        }, (err) => {
            this.error = err;
            this.done = true;
        });
    }

    resolve(value: T) {
        if (this.done)  {
            throw new Error('Promise already resolved');
        }
        if (this._resolve) {
            this._resolve(value);
        }
    };

    reject(err: any) {
        if (this.done)  {
            throw new Error('Promise already resolved');
        }
        if (this._reject) {
            this._reject(err);
        }
    };
}

class JWTAuthConsumer  {

    private readonly resourceName: string;

    private readonly requestHandler: ResolvablePromise<RequestHandler>;

    constructor(resourceName: string) {
        this.resourceName = resourceName;
        this.requestHandler = new ResolvablePromise<RequestHandler>()
        Config.onReady(async (provider) => {
            const handler = await this.createAuthHandler(provider);
            const requestHandler = await this.createRequestHandler(handler);
            this.requestHandler.resolve(requestHandler);
        });
    }

    public toExpress() {
        return createDelayedRequestHandler(this.requestHandler);
    }

    private async createAuthHandler(provider: ConfigProvider) {
        const keyStore = await this.createKeyStore(provider);
        return new JWTAuthHandler(keyStore);
    }

    private async createRequestHandler(handler: JWTAuthHandler) {
        return jwtAuthorization({
            handler
        });
    }

    private async createKeyStore(provider: ConfigProvider): Promise<JWTKeyStore> {
        let baseUrl = await provider.getServiceAddress(this.resourceName, PORT_TYPE);

        while (baseUrl && baseUrl.endsWith('/')) {
            baseUrl = baseUrl.substring(0, baseUrl.length - 1);
        }

        const response = await fetch(baseUrl + PATH_KAPETA_AUTHENTICATION, {
            headers: {
                'Accept': 'application/json'
            }
        });

        if (response.status !== 200) {
            console.error('Invalid response from Kapeta authentication service: %d', response.status, baseUrl + PATH_KAPETA_AUTHENTICATION);
            throw new Error('Invalid response from Kapeta authentication service: ' + response.status);
        }

        const metadata = await response.json() as KapetaAuthenticationMetadata;

        return new JWTKeyHandlerExternal(baseUrl + metadata.jwks, metadata.issuer, metadata.audience);
    }

}