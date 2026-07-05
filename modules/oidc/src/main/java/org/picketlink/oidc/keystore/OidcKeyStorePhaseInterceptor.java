package org.picketlink.oidc.keystore;

import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.apache.cxf.rs.security.jose.common.JoseConstants;
import org.apache.cxf.rt.security.rs.RSSecurityConstants;
import org.picketlink.oidc.OidcDemoConstants;

/**
 * Clears CXF exchange-level keystore cache and injects the live keystore before JOSE signing.
 * Used when ByteBuddy agent is not attached (WildFly in-process attach is unreliable).
 */
public final class OidcKeyStorePhaseInterceptor extends AbstractPhaseInterceptor<Message> {

    public OidcKeyStorePhaseInterceptor() {
        super(Phase.PRE_INVOKE);
    }

    @Override
    public void handleMessage(Message message) {
        DynamicOidcKeyStore store = DynamicOidcKeyStore.getGlobal();
        if (store == null) {
            return;
        }
        String file = store.keystorePath().toString();
        message.getExchange().remove(file);
        message.put(RSSecurityConstants.RSSEC_KEY_STORE, store.currentKeyStore());
        message.put(RSSecurityConstants.RSSEC_KEY_STORE_FILE, file);
        message.put(RSSecurityConstants.RSSEC_KEY_STORE_TYPE, store.currentKeyStore().getType());
        message.put(RSSecurityConstants.RSSEC_KEY_STORE_ALIAS, store.activeAlias());
        message.put(RSSecurityConstants.RSSEC_KEY_STORE_PSWD, OidcDemoConstants.KEYSTORE_PASSWORD);
        message.put(RSSecurityConstants.RSSEC_KEY_PSWD, OidcDemoConstants.KEYSTORE_KEY_PASSWORD);
        message.put(JoseConstants.RSSEC_SIGNATURE_ALGORITHM, "RS256");
    }
}
