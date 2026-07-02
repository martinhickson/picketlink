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
package org.picketlink.test.oauth.server.endpoint;

import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.webapp.WebAppContext;
import org.jboss.resteasy.plugins.server.servlet.HttpServletDispatcher;
import org.junit.After;
import org.picketlink.oauth.PicketLinkOAuthApplication;

import java.net.URL;

/**
 * Base class for the endpoint test cases
 *
 * @author anil saldhana
 * @since Sep 13, 2012
 */
public class EndpointTestBase extends EmbeddedWebServerBase {

    @After
    public void tearDown() throws Exception {
        super.tearDown();
        Thread.sleep(1000); // 1sec
    }

    @Override
    protected void establishUserApps() throws Exception {
        ClassLoader tcl = Thread.currentThread().getContextClassLoader();
        if (tcl == null) {
            tcl = getClass().getClassLoader();
        }

        final String WEBAPPDIR = "oauth";

        final String CONTEXTPATH = "/*";

        // for localhost:port/admin/index.html and whatever else is in the webapp directory
        final URL warUrl = tcl.getResource(WEBAPPDIR);
        final String warUrlString = warUrl.toExternalForm();

        // WebAppContext context = new WebAppContext(warUrlString, CONTEXTPATH);

        WebAppContext context = createWebApp(CONTEXTPATH, warUrlString);

        context.setExtraClasspath(warUrlString + "/..");

        context.setContextPath("/");
        ServletHolder servletHolder = new ServletHolder(new HttpServletDispatcher());
        servletHolder.setInitParameter("jakarta.ws.rs.Application", PicketLinkOAuthApplication.class.getName());
        context.addServlet(servletHolder, "/*");

        server.setHandler(context);
    }
}