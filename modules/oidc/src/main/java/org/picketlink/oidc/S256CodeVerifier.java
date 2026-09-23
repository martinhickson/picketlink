package org.picketlink.oidc;

import org.apache.cxf.rs.security.oauth2.grants.code.CodeVerifierTransformer;
import org.picketlink.oidc.provider.AuthorizationCodeService;

/**
 * RFC 7636 S256 transform for the CXF authorization-code grant. Verifiers outside the
 * 43–128 unreserved range transform to a value that cannot match a stored challenge.
 */
public final class S256CodeVerifier implements CodeVerifierTransformer {

    @Override
    public String transformCodeVerifier(String codeVerifier) {
        if (!AuthorizationCodeService.verifierAccepted(codeVerifier)) {
            return "";
        }
        return AuthorizationCodeService.s256(codeVerifier);
    }

    @Override
    public String getChallengeMethod() {
        return "S256";
    }
}
