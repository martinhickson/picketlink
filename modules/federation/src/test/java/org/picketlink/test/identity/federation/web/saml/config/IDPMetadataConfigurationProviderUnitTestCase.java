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
package org.picketlink.test.identity.federation.web.saml.config;

import org.junit.Test;
import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.config.federation.IDPType;
import org.picketlink.config.federation.TrustType;
import org.picketlink.identity.federation.web.config.IDPMetadataConfigurationProvider;

import java.io.InputStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Unit test the {@link IDPMetadataConfigurationProvider}
 *
 * @author Anil Saldhana
 * @since Feb 15, 2012
 */
public class IDPMetadataConfigurationProviderUnitTestCase {

    @Test
    public void testIDPType() throws ProcessingException {
        IDPMetadataConfigurationProvider provider = new IDPMetadataConfigurationProvider();
        IDPType idp = provider.getIDPConfiguration();
        assertNotNull(idp);
        assertEquals("https://idp.testshib.org/idp/profile/SAML2/POST/SSO", idp.getIdentityURL());
    }

    @SuppressWarnings("deprecation")
    @Test
    public void testIDPTypeWithConfig() throws Exception {
        IDPMetadataConfigurationProvider provider = new IDPMetadataConfigurationProvider();
        InputStream is = Thread.currentThread().getContextClassLoader()
                .getResourceAsStream("saml2/logout/idp/WEB-INF/picketlink-idfed-without-identity-url.xml");
        assertNotNull(is);
        provider.setConfigFile(is);

        IDPType idp = provider.getIDPConfiguration();
        assertNotNull(idp);
        assertEquals("https://idp.testshib.org/idp/profile/SAML2/POST/SSO", idp.getIdentityURL());

        TrustType trust = idp.getTrust();
        assertNotNull(trust);
        assertEquals("localhost,jboss.com,jboss.org", trust.getDomains());

        assertEquals("org.picketlink.identity.federation.core.impl.EmptyAttributeManager", idp.getAttributeManager());
    }
}