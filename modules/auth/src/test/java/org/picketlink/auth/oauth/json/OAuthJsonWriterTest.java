package org.picketlink.auth.oauth.json;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;
import org.picketlink.auth.oauth.model.OAuthErrorResponse;
import org.picketlink.auth.oauth.model.TokenResponse;

class OAuthJsonWriterTest {

    @Test
    void writesTokenResponseJson() {
        String json = OAuthJsonWriter.writeTokenResponse(
                new TokenResponse("token-value", "Bearer", 3600L, "api.read"));

        assertTrue(json.contains("\"access_token\":\"token-value\""));
        assertTrue(json.contains("\"token_type\":\"Bearer\""));
        assertTrue(json.contains("\"expires_in\":3600"));
        assertTrue(json.contains("\"scope\":\"api.read\""));
    }

    @Test
    void writesErrorResponseJson() {
        String json = OAuthJsonWriter.writeErrorResponse(
                new OAuthErrorResponse("invalid_client", "bad credentials"));

        assertTrue(json.contains("\"error\":\"invalid_client\""));
        assertTrue(json.contains("\"error_description\":\"bad credentials\""));
    }

    @Test
    void escapesControlCharacters() {
        assertEquals("\\\"quoted\\\"", OAuthJsonWriter.escape("\"quoted\""));
        assertEquals("line\\nbreak", OAuthJsonWriter.escape("line\nbreak"));
    }
}
