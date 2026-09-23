package org.picketlink.oidc;

import java.util.List;
import java.util.stream.Collectors;
import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.grants.code.DefaultEncryptingCodeDataProvider;
import org.apache.cxf.rs.security.oauth2.grants.code.ServerAuthorizationCodeGrant;
import org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException;

/**
 * OAuth client and code store filled from {@link OidcClientRegistration} values.
 */
public class ConfiguredOidcDataProvider extends DefaultEncryptingCodeDataProvider {

    public ConfiguredOidcDataProvider(List<OidcClientRegistration> clients) {
        super("AES", 128);
        if (clients == null || clients.isEmpty()) {
            throw new IllegalArgumentException("at least one client is required");
        }
        List<String> scopes = clients.stream()
                .flatMap(client -> client.getScopes().stream())
                .distinct()
                .collect(Collectors.toList());
        setSupportedScopes(scopes.stream().collect(Collectors.toMap(scope -> scope, scope -> scope)));
        for (OidcClientRegistration registration : clients) {
            setClient(toClient(registration));
        }
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
     * and parses them with a comma split that does not trim whitespace.
     */
    static Client normalizeListFields(Client client) {
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
                .filter(value -> !value.isEmpty())
                .collect(Collectors.toList());
    }

    private static Client toClient(OidcClientRegistration registration) {
        Client client = new Client(registration.getClientId(), registration.getClientSecret(), true);
        client.setApplicationName(registration.getApplicationName());
        client.setApplicationWebUri(registration.applicationWebUri());
        client.setRedirectUris(registration.getRedirectUris());
        client.setAllowedGrantTypes(registration.getGrantTypes());
        client.setRegisteredScopes(registration.getScopes());
        return client;
    }
}
