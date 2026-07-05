package org.picketlink.oidc;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.grants.code.DefaultEncryptingCodeDataProvider;
import org.apache.cxf.rs.security.oauth2.grants.code.ServerAuthorizationCodeGrant;
import org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;

public class DemoOidcDataProvider extends DefaultEncryptingCodeDataProvider {

    public DemoOidcDataProvider(String rpRedirectUri) {
        super("AES", 128);
        registerDemoClient(rpRedirectUri);
        setSupportedScopes(OidcDemoConstants.DEFAULT_SCOPES.stream()
                .collect(Collectors.toMap(s -> s, s -> s)));
    }

    @Override
    public Client doGetClient(String clientId) throws OAuthServiceException {
        return normalizeListFields(super.doGetClient(clientId));
    }

    @Override
    public void setClient(Client client) {
        super.setClient(normalizeListFields(client));
    }

    @Override
    public ServerAuthorizationCodeGrant removeCodeGrant(String code) throws OAuthServiceException {
        return normalizeGrant(super.removeCodeGrant(code));
    }

    /**
     * CXF {@code ModelEncryptionSupport} serializes list fields via {@code List.toString()}
     * (e.g. {@code [openid, profile]}) and parses them with a comma split that does not trim
     * whitespace, so multi-scope clients round-trip as {@code profile} → {@code " profile"}.
     */
    private static Client normalizeListFields(Client client) {
        client.setRegisteredScopes(trimList(client.getRegisteredScopes()));
        client.setRedirectUris(trimList(client.getRedirectUris()));
        client.setAllowedGrantTypes(trimList(client.getAllowedGrantTypes()));
        client.setRegisteredAudiences(trimList(client.getRegisteredAudiences()));
        client.setApplicationCertificates(trimList(client.getApplicationCertificates()));
        return client;
    }

    private static ServerAuthorizationCodeGrant normalizeGrant(ServerAuthorizationCodeGrant grant) {
        if (grant == null) {
            return null;
        }
        if (grant.getClient() != null) {
            normalizeListFields(grant.getClient());
        }
        grant.setApprovedScopes(trimList(grant.getApprovedScopes()));
        grant.setRequestedScopes(trimList(grant.getRequestedScopes()));
        return grant;
    }

    private static List<String> trimList(List<String> values) {
        if (values == null || values.isEmpty()) {
            return values;
        }
        return values.stream()
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());
    }

    private void registerDemoClient(String rpRedirectUri) {
        Client client = new Client(
                OidcDemoConstants.CLIENT_ID,
                OidcDemoConstants.CLIENT_SECRET,
                true);
        client.setApplicationName("PicketLink Demo RP");
        client.setApplicationWebUri(rpRedirectUri.substring(0, rpRedirectUri.lastIndexOf("/oidc/") + 1));
        client.setRedirectUris(Arrays.asList(rpRedirectUri));
        client.setAllowedGrantTypes(Arrays.asList(
                OAuthConstants.AUTHORIZATION_CODE_GRANT,
                OAuthConstants.REFRESH_TOKEN_GRANT));
        client.setRegisteredScopes(OidcDemoConstants.DEFAULT_SCOPES);
        setClient(client);
    }
}
