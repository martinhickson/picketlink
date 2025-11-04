package org.picketlink.identity.federation.web.config;

import jakarta.servlet.ServletContext;
import java.io.IOException;
import java.util.Map;

/**
 * Interface for obtaining the Identity Provider Mapping
 *
 * @author Anil Saldhana
 */
public interface IdentityURLConfigurationProvider {

    /**
     * Set the servlet context for resources on web classpath
     * @param servletContext
     */
    void setServletContext(ServletContext servletContext);
    /**
     * Set a {@link ClassLoader} for the Provider
     * @param classLoader
     */
    void setClassLoader(ClassLoader classLoader);
    /**
     * Get a map of AccountName versus IDP URLs
     * @return
     */
    Map<String,String> getIDPMap() throws IOException;
}
