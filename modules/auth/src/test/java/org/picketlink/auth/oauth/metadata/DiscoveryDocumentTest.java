package org.picketlink.auth.oauth.metadata;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.picketlink.auth.oauth.OAuthConstants;

class DiscoveryDocumentTest {

    @Test
    void bothWellKnownPathsDescribeTheSameGrants() {
        OAuthAuthorizationServerMetadata metadata = new OAuthAuthorizationServerMetadata(
                "https://issuer.example",
                "https://issuer.example/token",
                "https://issuer.example/authorize",
                "https://issuer.example/jwks",
                List.of(OAuthConstants.CLIENT_CREDENTIALS_GRANT, OAuthConstants.PASSWORD_GRANT,
                        OAuthConstants.REFRESH_TOKEN_GRANT),
                List.of("openid", "api.read"),
                List.of("RS256"));

        String oauth = new OAuthAuthorizationServerMetadataResource(metadata).metadataDocument();
        String openid = new OpenIdProviderMetadataResource(metadata).metadataDocument();
        assertEquals(oauth, openid);
        assertTrue(oauth.contains("\"grant_types_supported\":[\"client_credentials\",\"password\",\"refresh_token\"]"));
        assertTrue(oauth.contains("\"jwks_uri\":\"https://issuer.example/jwks\""));
        assertTrue(oauth.contains("\"id_token_signing_alg_values_supported\":[\"RS256\"]"));
    }
}
