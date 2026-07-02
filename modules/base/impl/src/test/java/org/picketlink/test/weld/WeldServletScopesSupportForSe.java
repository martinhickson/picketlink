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

import jakarta.enterprise.context.RequestScoped;
import jakarta.enterprise.context.SessionScoped;
import jakarta.enterprise.context.spi.Context;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.spi.AfterDeploymentValidation;
import jakarta.enterprise.inject.spi.BeanManager;
import jakarta.enterprise.inject.spi.Extension;
import org.jboss.weld.context.ManagedContext;

/**
 * Activates request and session scopes in Weld SE for servlet-oriented tests.
 */
public class WeldServletScopesSupportForSe implements Extension {

    public void afterDeployment(@Observes AfterDeploymentValidation event, BeanManager beanManager) {
        activateContext(beanManager, RequestScoped.class);
        activateContext(beanManager, SessionScoped.class);
    }

    private void activateContext(BeanManager beanManager, Class<? extends java.lang.annotation.Annotation> scope) {
        Context context = beanManager.getContext(scope);
        if (context instanceof ManagedContext) {
            ((ManagedContext) context).activate();
        }
    }
}
