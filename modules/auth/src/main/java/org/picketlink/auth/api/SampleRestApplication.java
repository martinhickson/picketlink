package org.picketlink.auth.api;

import jakarta.ws.rs.ApplicationPath;
import jakarta.ws.rs.core.Application;
import java.util.Set;

@ApplicationPath("/")
public class SampleRestApplication extends Application {

    @Override
    public Set<Class<?>> getClasses() {
        return Set.of(VersionResource.class, UserResource.class);
    }
}
