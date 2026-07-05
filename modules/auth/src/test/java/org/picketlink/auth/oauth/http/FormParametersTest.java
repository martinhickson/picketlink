package org.picketlink.auth.oauth.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.picketlink.auth.oauth.OAuthConstants;

class FormParametersTest {

    @Test
    void parsesUrlEncodedBody() {
        Map<String, String> params = FormParameters.parse(
                "grant_type=client_credentials&client_id=demo&client_secret=s%2Becret&scope=api.read");

        assertEquals(OAuthConstants.CLIENT_CREDENTIALS_GRANT, params.get(OAuthConstants.GRANT_TYPE));
        assertEquals("demo", params.get(OAuthConstants.CLIENT_ID));
        assertEquals("s+ecret", params.get(OAuthConstants.CLIENT_SECRET));
        assertEquals("api.read", params.get(OAuthConstants.SCOPE));
    }

    @Test
    void returnsEmptyMapForBlankBody() {
        assertTrue(FormParameters.parse("").isEmpty());
        assertTrue(FormParameters.parse(null).isEmpty());
    }
}
