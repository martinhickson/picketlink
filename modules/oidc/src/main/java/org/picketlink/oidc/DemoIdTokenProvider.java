package org.picketlink.oidc;

import java.util.List;
import org.apache.cxf.rs.security.oauth2.common.UserSubject;
import org.apache.cxf.rs.security.oidc.common.IdToken;
import org.apache.cxf.rs.security.oidc.idp.IdTokenProvider;

public class DemoIdTokenProvider implements IdTokenProvider {

    private final String issuer;

    public DemoIdTokenProvider(String issuer) {
        this.issuer = issuer;
    }

    @Override
    public IdToken getIdToken(String clientId, UserSubject subject, List<String> scopes) {
        IdToken token = new IdToken();
        token.setIssuer(issuer);
        token.setSubject(subject.getLogin());
        token.setAudience(clientId);
        token.setPreferredUserName(subject.getLogin());
        token.setName(subject.getLogin());
        token.setAuthorizedParty(clientId);
        long now = System.currentTimeMillis() / 1000L;
        token.setIssuedAt(now);
        token.setExpiryTime(now + 3600);
        token.setAuthenticationTime(now);
        return token;
    }
}
