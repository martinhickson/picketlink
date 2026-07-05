package org.picketlink.oidc.keystore;

import java.security.KeyStore;
import java.util.Properties;

import org.apache.cxf.message.Message;
import org.apache.cxf.rt.security.rs.RSSecurityConstants;

import net.bytebuddy.asm.Advice;

/**
 * Advice injected into {@code KeyManagementUtils.loadPersistKeyStore} so CXF always
 * reads the latest signing keys from {@link DynamicOidcKeyStore}.
 */
public final class OidcKeyStoreAdvice {

    private OidcKeyStoreAdvice() {
    }

    @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
    static KeyStore enter(@Advice.Argument(0) Message message, @Advice.Argument(1) Properties props) {
        DynamicOidcKeyStore store = DynamicOidcKeyStore.getGlobal();
        if (store == null || props == null) {
            return null;
        }
        String file = props.getProperty(RSSecurityConstants.RSSEC_KEY_STORE_FILE);
        if (!store.manages(file)) {
            return null;
        }
        if (message != null && file != null) {
            message.getExchange().remove(file);
        }
        return store.currentKeyStore();
    }

    @Advice.OnMethodExit
    static void exit(@Advice.Enter KeyStore injected, @Advice.Return(readOnly = false) KeyStore returned) {
        if (injected != null) {
            returned = injected;
        }
    }
}
