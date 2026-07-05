package org.picketlink.idm.admin.realm.elytron;

import java.security.Principal;
import java.security.spec.AlgorithmParameterSpec;
import org.picketlink.idm.document.IdmDocumentStores;
import org.picketlink.idm.document.IdmRealmService;
import org.picketlink.idm.document.IdmUserRecord;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.PasswordGuessEvidence;

/**
 * Elytron {@link SecurityRealm} backed by the pluggable IDM JSON document store.
 * Replaces static {@code properties-realm} for OIDC Authorization Server FORM login.
 */
public class PicketLinkIdmDocumentSecurityRealm implements SecurityRealm {

    private final IdmRealmService realmService = new IdmRealmService();

    @Override
    public RealmIdentity getRealmIdentity(Evidence evidence) throws RealmUnavailableException {
        if (!(evidence instanceof PasswordGuessEvidence)) {
            return RealmIdentity.NON_EXISTENT;
        }
        PasswordGuessEvidence guess = (PasswordGuessEvidence) evidence;
        String loginName = guess.getPrincipal().getName();
        try {
            char[] password = guess.getGuess();
            return realmService.findUser(IdmDocumentStores.DEFAULT_DOCUMENT_ID, loginName)
                    .filter(user -> realmService.verifyPassword(user, password))
                    .map(this::identityFor)
                    .orElse(RealmIdentity.NON_EXISTENT);
        } catch (Exception ex) {
            throw new RealmUnavailableException(ex);
        } finally {
            guess.destroy();
        }
    }

    @Override
    public RealmIdentity getRealmIdentity(Principal principal) throws RealmUnavailableException {
        if (principal == null) {
            return RealmIdentity.NON_EXISTENT;
        }
        try {
            return realmService.findUser(IdmDocumentStores.DEFAULT_DOCUMENT_ID, principal.getName())
                    .map(this::identityFor)
                    .orElse(RealmIdentity.NON_EXISTENT);
        } catch (Exception ex) {
            throw new RealmUnavailableException(ex);
        }
    }

    private RealmIdentity identityFor(final IdmUserRecord user) {
        return new RealmIdentity() {
            @Override
            public Principal getRealmIdentityPrincipal() {
                return () -> user.getLoginName();
            }

            @Override
            public SupportLevel getCredentialAcquireSupport(
                    Class<? extends Credential> credentialType, String algorithmName,
                    AlgorithmParameterSpec parameterSpec) {
                return SupportLevel.UNSUPPORTED;
            }

            @Override
            public <C extends Credential> C getCredential(Class<C> credentialType) {
                return null;
            }

            @Override
            public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) {
                return PasswordGuessEvidence.class.isAssignableFrom(evidenceType)
                        ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
            }

            @Override
            public boolean verifyEvidence(Evidence evidence) throws RealmUnavailableException {
                if (evidence instanceof PasswordGuessEvidence) {
                    PasswordGuessEvidence guess = (PasswordGuessEvidence) evidence;
                    try {
                        return realmService.verifyPassword(user, guess.getGuess());
                    } finally {
                        guess.destroy();
                    }
                }
                return false;
            }

            @Override
            public boolean exists() {
                return user.isEnabled();
            }

            @Override
            public AuthorizationIdentity getAuthorizationIdentity() {
                MapAttributes attributes = new MapAttributes();
                int index = 0;
                for (String role : user.getRoles()) {
                    attributes.add("groups", index++, role);
                }
                return AuthorizationIdentity.basicIdentity(attributes);
            }
        };
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(
            Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) {
        return SupportLevel.UNSUPPORTED;
    }

    @Override
    public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) {
        return PasswordGuessEvidence.class.isAssignableFrom(evidenceType)
                ? SupportLevel.POSSIBLY_SUPPORTED : SupportLevel.UNSUPPORTED;
    }
}
