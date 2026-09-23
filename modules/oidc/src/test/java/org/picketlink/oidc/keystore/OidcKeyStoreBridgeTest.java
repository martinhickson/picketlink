package org.picketlink.oidc.keystore;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.lang.reflect.Method;
import java.security.KeyStore;
import java.util.Properties;

import org.junit.jupiter.api.Test;
import org.picketlink.oidc.keystore.bridge.OidcKeyStoreBridge;

class OidcKeyStoreBridgeTest {

    @Test
    void publishedStoreIsReturnedForTheManagedFile() throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, new char[0]);
        OidcKeyStoreBridge.publish("/tmp/maketest/oidc-signing.p12", store);

        Properties props = new Properties();
        props.setProperty(OidcKeyStoreBridge.KEYSTORE_FILE, "/tmp/maketest/oidc-signing.p12");
        assertSame(store, OidcKeyStoreBridge.enter(null, props));
        assertSame(store, OidcKeyStoreBridge.current());
    }

    @Test
    void aDifferentFileIsLeftToCxf() throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, new char[0]);
        OidcKeyStoreBridge.publish("/tmp/maketest/oidc-signing.p12", store);

        Properties props = new Properties();
        props.setProperty(OidcKeyStoreBridge.KEYSTORE_FILE, "/tmp/maketest/other.p12");
        assertNull(OidcKeyStoreBridge.enter(null, props));
    }

    @Test
    void adviceDoesNotLinkCxfTypes() {
        for (Method method : OidcKeyStoreAdvice.class.getDeclaredMethods()) {
            for (Class<?> type : method.getParameterTypes()) {
                if (type.getName().startsWith("org.apache.cxf.")) {
                    throw new AssertionError(method.getName() + " links " + type.getName());
                }
            }
            if (method.getReturnType().getName().startsWith("org.apache.cxf.")) {
                throw new AssertionError(method.getName() + " returns " + method.getReturnType().getName());
            }
        }
    }
}
