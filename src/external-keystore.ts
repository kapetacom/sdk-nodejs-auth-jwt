import {ConfigProvider} from "@kapeta/sdk-config";
import {JWTKeyHandlerExternal, JWTKeyStore} from "./keystores";
import {KapetaAuthenticationMetadata, PATH_KAPETA_AUTHENTICATION, PORT_TYPE} from "./types";

export async function createExternalKeyStore(resourceName: string, provider: ConfigProvider): Promise<JWTKeyStore> {
    let baseUrl = await provider.getServiceAddress(resourceName, PORT_TYPE);

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
