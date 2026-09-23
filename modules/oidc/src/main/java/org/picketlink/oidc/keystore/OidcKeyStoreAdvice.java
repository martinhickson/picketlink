package org.picketlink.oidc.keystore;

import java.security.KeyStore;

import org.picketlink.oidc.keystore.bridge.OidcKeyStoreBridge;

import net.bytebuddy.asm.Advice;

/**
 * Advice injected into {@code KeyManagementUtils.loadPersistKeyStore} so CXF
 * reads the keystore {@link OidcKeyStoreBridge} last published. The JDK does
 * not reload a {@link KeyStore} when the file on disk is replaced.
 */
public final class OidcKeyStoreAdvice {

    private OidcKeyStoreAdvice() {
    }

    @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
    static KeyStore enter(@Advice.Argument(0) Object message, @Advice.Argument(1) Object props) {
        return OidcKeyStoreBridge.enter(message, props);
    }

    @Advice.OnMethodExit
    static void exit(@Advice.Enter KeyStore injected, @Advice.Return(readOnly = false) KeyStore returned) {
        if (injected != null) {
            returned = injected;
        }
    }
}
