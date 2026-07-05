package org.picketlink.idm.admin.it.deployment;

import java.io.File;
import java.io.FilenameFilter;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;

public final class IdmAdminDeployments {

    private IdmAdminDeployments() {
    }

    public static WebArchive adminWar() {
        return ShrinkWrap.create(WebArchive.class, "idm-admin.war")
                .addAsWebInfResource(IdmAdminDeployments.class.getResource("/deployments/idm-admin-war/web.xml"), "web.xml")
                .addAsWebInfResource(IdmAdminDeployments.class.getResource("/deployments/idm-admin-war/jboss-web.xml"), "jboss-web.xml")
                .addAsLibraries(itLibraries());
    }

    private static File[] itLibraries() {
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
