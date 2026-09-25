package org.picketlink.auth.api;

import jakarta.ws.rs.core.Application;
import java.util.Set;

/**
 * Demo resources only. Not annotated with {@code @ApplicationPath}, so RESTEasy does not
 * deploy it beside {@code AdminApiServlet}. Register it from the application that wants it.
 */
public class SampleRestApplication extends Application {

    @Override
    public Set<Class<?>> getClasses() {
        return Set.of(VersionResource.class, UserResource.class);
    }
}
