package org.picketlink.oidc.keystore;

/**
 * {@code -javaagent} entry point. The JDK will not reload a keystore that is
 * already in memory, so this agent is what lets an expired signing certificate
 * be replaced without restarting the server.
 */
public final class OidcKeyStoreAgent {

    private OidcKeyStoreAgent() {
    }

    public static void premain(String agentArgs, java.lang.instrument.Instrumentation instrumentation) {
        OidcKeyStoreInstrumentation.installOn(instrumentation);
        System.err.println("OIDC keystore Byte Buddy agent installed");
    }

    public static void agentmain(String agentArgs, java.lang.instrument.Instrumentation instrumentation) {
        premain(agentArgs, instrumentation);
    }
}
