package org.picketlink.auth.it.deployment;

import java.io.File;
import java.io.FilenameFilter;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;

public final class AuthUiDeployments {

    private AuthUiDeployments() {
    }

    public static WebArchive authWar() {
        return ShrinkWrap.create(WebArchive.class, "auth.war")
                .addAsWebInfResource(AuthUiDeployments.class.getResource("/deployments/auth-war/web.xml"), "web.xml")
                .addAsWebInfResource(AuthUiDeployments.class.getResource("/deployments/auth-war/jboss-web.xml"), "jboss-web.xml")
                .addAsLibraries(authLibraries());
    }

    public static WebArchive apiWar() {
        return ShrinkWrap.create(WebArchive.class, "api.war")
                .addAsWebInfResource(AuthUiDeployments.class.getResource("/deployments/api-war/web.xml"), "web.xml")
                .addAsWebInfResource(AuthUiDeployments.class.getResource("/deployments/api-war/jboss-web.xml"), "jboss-web.xml")
                .addAsLibraries(authLibraries());
    }

    private static File[] authLibraries() {
        File libDir = new File("target/test-libs");
        File[] libraries = libDir.listFiles(new FilenameFilter() {
            public boolean accept(File dir, String name) {
                return name.endsWith(".jar");
            }
        });
        if (libraries == null || libraries.length == 0) {
            throw new IllegalStateException("Missing libraries in target/test-libs; run mvn generate-test-resources first");
        }
        return libraries;
    }
}
