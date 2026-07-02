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
package org.picketlink.test.scim.endpoints;

import java.io.Serializable;
import java.net.URL;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.Persistence;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.webapp.WebAppContext;
import org.jboss.resteasy.plugins.server.servlet.HttpServletDispatcher;
import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.PartitionManager;
import org.picketlink.idm.RelationshipManager;
import org.picketlink.idm.config.IdentityConfigurationBuilder;
import org.picketlink.idm.credential.Password;
import org.picketlink.idm.internal.DefaultPartitionManager;
import org.picketlink.idm.jpa.internal.JPAIdentityStore;
import org.picketlink.idm.jpa.model.sample.simple.AccountTypeEntity;
import org.picketlink.idm.jpa.model.sample.simple.AttributeTypeEntity;
import org.picketlink.idm.jpa.model.sample.simple.DigestCredentialTypeEntity;
import org.picketlink.idm.jpa.model.sample.simple.GroupTypeEntity;
import org.picketlink.idm.jpa.model.sample.simple.IdentityTypeEntity;
import org.picketlink.idm.jpa.model.sample.simple.OTPCredentialTypeEntity;
import org.picketlink.idm.jpa.model.sample.simple.PartitionTypeEntity;
import org.picketlink.idm.jpa.model.sample.simple.PasswordCredentialTypeEntity;
import org.picketlink.idm.jpa.model.sample.simple.RelationshipIdentityTypeEntity;
import org.picketlink.idm.jpa.model.sample.simple.RelationshipTypeEntity;
import org.picketlink.idm.jpa.model.sample.simple.RoleTypeEntity;
import org.picketlink.idm.jpa.model.sample.simple.X509CredentialTypeEntity;
import org.picketlink.idm.model.Attribute;
import org.picketlink.idm.model.basic.BasicModel;
import org.picketlink.idm.model.basic.Group;
import org.picketlink.idm.model.basic.Realm;
import org.picketlink.idm.model.basic.Role;
import org.picketlink.idm.model.basic.User;
import org.picketlink.idm.spi.ContextInitializer;
import org.picketlink.idm.spi.IdentityContext;
import org.picketlink.idm.spi.IdentityStore;
import org.picketlink.scim.PicketLinkSCIMApplication;
import org.picketlink.test.scim.EmbeddedWebServerBase;

/**
 * Base class for the SCIM Endpoint tests
 *
 * @author anil saldhana
 * @since Apr 17, 2013
 */
public abstract class AbstractEndpointTestCase extends EmbeddedWebServerBase {

    protected void populateIDM() {
        if (Thread.currentThread().getContextClassLoader() == null) {
            Thread.currentThread().setContextClassLoader(getClass().getClassLoader());
        }

        EntityManagerFactory entityManagerFactory = Persistence.createEntityManagerFactory("picketlink-scim-pu");
        EntityManager entityManager = entityManagerFactory.createEntityManager();
        entityManager.getTransaction().begin();

        IdentityConfigurationBuilder builder = new IdentityConfigurationBuilder();

        builder
            .named("default")
                .stores()
                    .jpa().mappedEntity(
                AccountTypeEntity.class,
                RoleTypeEntity.class,
                GroupTypeEntity.class,
                IdentityTypeEntity.class,
                RelationshipTypeEntity.class,
                RelationshipIdentityTypeEntity.class,
                PartitionTypeEntity.class,
                PasswordCredentialTypeEntity.class,
                DigestCredentialTypeEntity.class,
                X509CredentialTypeEntity.class,
                OTPCredentialTypeEntity.class,
                AttributeTypeEntity.class
            ).addContextInitializer(new ContextInitializer() {
                @Override
                public void initContextForStore(IdentityContext ctx, IdentityStore<?> store) {
                    if (store instanceof JPAIdentityStore) {
                        if (!ctx.isParameterSet(JPAIdentityStore.INVOCATION_CTX_ENTITY_MANAGER)) {
                            ctx.setParameter(JPAIdentityStore.INVOCATION_CTX_ENTITY_MANAGER, entityManager);
                        }
                    }
                }
            }).supportAllFeatures();

        PartitionManager partitionManager = new DefaultPartitionManager(builder.build());

        if (partitionManager.getPartition(Realm.class, Realm.DEFAULT_REALM) == null) {
            partitionManager.add(new Realm(Realm.DEFAULT_REALM));
        }

        IdentityManager identityManager = partitionManager.createIdentityManager();

        User anil = BasicModel.getUser(identityManager, "anil");

        if (anil == null) {
            User admin = new User("anil");
            admin.setAttribute(new Attribute<Serializable>("ID", "1234"));
            admin.setEmail("admin@acme.com");

            identityManager.add(admin);
            identityManager.updateCredential(admin, new Password("tough"));

            Role roleAdmin = new Role("administrator");
            identityManager.add(roleAdmin);

            RelationshipManager relationshipManager = partitionManager.createRelationshipManager();

            BasicModel.grantRole(relationshipManager, admin, roleAdmin);

            Group group = new Group("SomeGroup");
            group.setAttribute(new Attribute<String>("ID", "jboss"));
            identityManager.add(group);
        }

        entityManager.getTransaction().commit();
        entityManager.close();
        entityManagerFactory.close();
    }

    @Override
    protected void establishUserApps() throws Exception {
        populateIDM();

        ClassLoader tcl = Thread.currentThread().getContextClassLoader();
        if (tcl == null) {
            tcl = getClass().getClassLoader();
        }

        final String WEBAPPDIR = "scim";
        final String CONTEXTPATH = "/*";

        final URL warUrl = tcl.getResource(WEBAPPDIR);
        final String warUrlString = warUrl.toExternalForm();

        WebAppContext context = createWebApp(CONTEXTPATH, warUrlString);
        context.setExtraClasspath(warUrlString + "/..");
        context.setContextPath("/");

        ServletHolder servletHolder = new ServletHolder(new HttpServletDispatcher());
        servletHolder.setInitParameter("jakarta.ws.rs.Application", PicketLinkSCIMApplication.class.getName());
        context.addServlet(servletHolder, "/*");

        server.setHandler(context);
    }
}
