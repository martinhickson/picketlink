/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2012, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.picketlink.test.weld;

import org.jboss.weld.context.bound.BoundRequestContext;
import org.jboss.weld.context.bound.BoundSessionContext;
import org.jboss.weld.environment.se.WeldContainer;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.model.InitializationError;
import org.junit.runners.model.TestClass;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Pedro Igor
 */
public class WeldRunner extends BlockJUnit4ClassRunner {

    private WeldContainer container;

    public WeldRunner(Class<?> klass) throws InitializationError {
        super(klass);
    }

    @Override
    protected Object createTest() throws Exception {
        TestClass testClass = getTestClass();
        Class<?> klass = testClass.getJavaClass();
        Deployment deploymentConfig = klass.getAnnotation(Deployment.class);

        if (deploymentConfig == null) {
            throw new IllegalArgumentException("Test class [" + klass + "] does not provide a @Deployment annotation.");
        }

        String excludePackage = deploymentConfig.excludeBeansFromPackage();

        if (excludePackage.isEmpty()) {
            excludePackage = klass.getPackage().getName();
        }

        WeldTest weld = new WeldTest()
            .excludeBeansFromPackage(excludePackage)
            .addClass(klass);

        for (Class<?> beanClass : deploymentConfig.beans()) {
            weld.addClass(beanClass);
        }

        this.container = weld.initialize();
        activateRequestAndSessionScopes(this.container);

        return container.instance().select(klass).get();
    }

    private static void activateRequestAndSessionScopes(WeldContainer container) {
        Map<String, Object> requestMap = new HashMap<>();
        Map<String, Object> sessionMap = new HashMap<>();

        BoundRequestContext requestContext = container.select(BoundRequestContext.class).get();
        requestContext.associate(requestMap);
        requestContext.activate();

        BoundSessionContext sessionContext = container.select(BoundSessionContext.class).get();
        sessionContext.associate(sessionMap);
        sessionContext.activate();
    }
}
