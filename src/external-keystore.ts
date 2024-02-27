import { ConfigProvider } from '@kapeta/sdk-config';
import { JWTKeyHandlerExternal, JWTKeyStore } from './keystores';
import { KapetaAuthenticationMetadata, PATH_KAPETA_AUTHENTICATION, PORT_TYPE } from './types';

export async function createExternalKeyStore(resourceName: string, provider: ConfigProvider): Promise<JWTKeyStore> {
    let baseUrl = await provider.getServiceAddress(resourceName, PORT_TYPE);

    while (baseUrl && baseUrl.endsWith('/')) {
        baseUrl = baseUrl.substring(0, baseUrl.length - 1);
    }

    const authUrl = baseUrl + PATH_KAPETA_AUTHENTICATION;
    const metadata = await fetchMetadataWithRetry(authUrl);

    return new JWTKeyHandlerExternal(baseUrl + metadata.jwks, metadata.issuer, metadata.audience);
}

async function fetchMetadataWithRetry(authUrl: string): Promise<KapetaAuthenticationMetadata> {
    while (true) {
        try {
            console.info("Attempting to fetch Kapeta authentication metadata from url: " + authUrl);
            return await fetchMetadata(authUrl);
        } catch (e) {
            await new Promise(resolve => setTimeout(resolve, 2000));
        }
    }
}

async function fetchMetadata(authUrl: string): Promise<KapetaAuthenticationMetadata> {
    const response = await fetch(authUrl, {
        headers: {
            Accept: 'application/json',
        },
    });

    if (response.status !== 200) {
        console.error(
            'Invalid response from Kapeta authentication service: %d',
            response.status,
            authUrl
        );
        throw new Error('Invalid response from Kapeta authentication service: ' + response.status);
    }

    return (await response.json()) as KapetaAuthenticationMetadata
}
