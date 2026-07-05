package org.picketlink.oidc.keystore;

import java.lang.instrument.Instrumentation;
import java.util.logging.Level;
import java.util.logging.Logger;

import net.bytebuddy.agent.ByteBuddyAgent;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.matcher.ElementMatchers;

public final class OidcKeyStoreInstrumentation {

    private static final Logger LOG = Logger.getLogger(OidcKeyStoreInstrumentation.class.getName());
    private static volatile boolean installed;

    private OidcKeyStoreInstrumentation() {
    }

    public static void ensureInstalled() {
        if (installed) {
            return;
        }
        synchronized (OidcKeyStoreInstrumentation.class) {
            if (installed) {
                return;
            }
            try {
                Instrumentation inst = ByteBuddyAgent.install();
                installOn(inst);
                installed = true;
                LOG.info("Installed OIDC dynamic keystore ByteBuddy instrumentation");
            } catch (Throwable ex) {
                LOG.log(Level.WARNING,
                        "OIDC keystore instrumentation unavailable; use -javaagent for cert rotation support",
                        ex);
            }
        }
    }

    public static void installOn(Instrumentation instrumentation) {
        new AgentBuilder.Default()
                .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
                .ignore(ElementMatchers.nameStartsWith("net.bytebuddy."))
                .ignore(ElementMatchers.nameStartsWith("org.picketlink.oidc.keystore."))
                .type(ElementMatchers.named("org.apache.cxf.rs.security.jose.common.KeyManagementUtils"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .method(ElementMatchers.named("loadPersistKeyStore")
                                .and(ElementMatchers.takesArguments(2)))
                        .intercept(Advice.to(OidcKeyStoreAdvice.class)))
                .installOn(instrumentation);
        installed = true;
    }
}
