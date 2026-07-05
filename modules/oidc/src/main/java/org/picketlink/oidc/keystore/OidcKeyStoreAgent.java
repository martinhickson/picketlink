package org.picketlink.oidc.keystore;

/**
 * Optional {@code -javaagent} entry point for environments where in-process
 * {@link ByteBuddyAgent#install()} is restricted.
 */
public final class OidcKeyStoreAgent {

    private OidcKeyStoreAgent() {
    }

    public static void premain(String agentArgs, java.lang.instrument.Instrumentation instrumentation) {
        OidcKeyStoreInstrumentation.installOn(instrumentation);
    }

    public static void agentmain(String agentArgs, java.lang.instrument.Instrumentation instrumentation) {
        premain(agentArgs, instrumentation);
    }
}
