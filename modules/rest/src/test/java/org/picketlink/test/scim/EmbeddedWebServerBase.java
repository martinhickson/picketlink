/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.picketlink.test.scim;

import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.FilterMapping;
import org.eclipse.jetty.webapp.WebAppContext;
import org.junit.After;
import org.junit.Before;

/**
 * Base class for embedded web server based tests
 *
 * @author Anil Saldhana
 * @since Jul 8, 2009
 */
public abstract class EmbeddedWebServerBase {
    protected Server server = null;
    private ClassLoader originalContextClassLoader;

    @Before
    public void setUp() throws Exception {
        originalContextClassLoader = Thread.currentThread().getContextClassLoader();

        server = new Server();
        server.setConnectors(getConnectors());
        this.establishUserApps();
        server.start();
    }

    @After
    public void tearDown() throws Exception {
        if (server != null) {
            server.stop();
            try {
                server.destroy();
            } catch (Exception e) {
                e.printStackTrace();
            }
            server = null;
        }
        Thread.currentThread().setContextClassLoader(originalContextClassLoader);
    }

    protected Connector[] getConnectors() {
        ServerConnector connector = new ServerConnector(server);
        connector.setPort(11080);
        return new Connector[] { connector };
    }

    protected abstract void establishUserApps() throws Exception;

    protected FilterMapping createFilterMapping(String pathSpec, FilterHolder filterHolder) {
        FilterMapping filterMapping = new FilterMapping();
        filterMapping.setPathSpec(pathSpec);
        filterMapping.setFilterName(filterHolder.getName());
        return filterMapping;
    }

    protected WebAppContext createWebApp(String contextPath, String warURLString) {
        WebAppContext webapp = new WebAppContext();
        webapp.setContextPath(contextPath);
        webapp.setWar(warURLString);

        Thread.currentThread().setContextClassLoader(webapp.getClassLoader());
        return webapp;
    }
}
