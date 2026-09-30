/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2026 PicketLink contributors.
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
package org.picketlink.test.identity.federation.web.handlers.saml2;

import static org.junit.Assert.assertEquals;

import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.datatype.XMLGregorianCalendar;

import org.junit.Before;
import org.junit.Test;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.identity.federation.core.saml.v2.util.XMLTimeUtil;
import org.picketlink.config.federation.IDPType;
import org.picketlink.identity.federation.core.interfaces.RoleGenerator;
import org.picketlink.identity.federation.core.saml.v2.common.SAMLDocumentHolder;
import org.picketlink.identity.federation.core.saml.v2.impl.DefaultSAML2HandlerChainConfig;
import org.picketlink.identity.federation.core.saml.v2.impl.DefaultSAML2HandlerRequest;
import org.picketlink.identity.federation.core.saml.v2.impl.DefaultSAML2HandlerResponse;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2Handler;
import org.picketlink.identity.federation.saml.v2.protocol.AuthnRequestType;
import org.picketlink.identity.federation.web.core.HTTPContext;
import org.picketlink.identity.federation.web.handlers.saml2.RolesGenerationHandler;
import org.picketlink.test.identity.federation.web.mock.MockHttpServletRequest;
import org.picketlink.test.identity.federation.web.mock.MockHttpSession;

public class RolesGenerationHandlerEmptySessionTestCase {

    @Before
    public void resetGenerator() {
        ScriptedGenerator.calls = 0;
        ScriptedGenerator.next = Collections.singletonList("sonata-web");
    }

    @Test
    public void emptySessionListIsGeneratedAgain() throws Exception {
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(GeneralConstants.ROLES_ID, Collections.emptyList());
        DefaultSAML2HandlerResponse response = handle(session);

        assertEquals(1, ScriptedGenerator.calls);
        assertEquals(Collections.singletonList("sonata-web"), session.getAttribute(GeneralConstants.ROLES_ID));
        assertEquals(Collections.singletonList("sonata-web"), response.getRoles());
    }

    @Test
    public void existingRolesAreKept() throws Exception {
        ScriptedGenerator.next = null;
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(GeneralConstants.ROLES_ID, Arrays.asList("sonata-staff"));
        DefaultSAML2HandlerResponse response = handle(session);

        assertEquals(0, ScriptedGenerator.calls);
        assertEquals(Arrays.asList("sonata-staff"), response.getRoles());
    }

    private static DefaultSAML2HandlerResponse handle(MockHttpSession session) throws Exception {
        RolesGenerationHandler handler = new RolesGenerationHandler();
        IDPType idp = new IDPType();
        idp.setRoleGenerator(ScriptedGenerator.class.getName());
        Map<String, Object> parameters = new HashMap<String, Object>();
        parameters.put(GeneralConstants.CONFIGURATION, idp);
        handler.initChainConfig(new DefaultSAML2HandlerChainConfig(parameters));

        XMLGregorianCalendar instant = XMLTimeUtil.getIssueInstant();
        AuthnRequestType authnRequest = new AuthnRequestType("ID_1", instant);
        HTTPContext context = new HTTPContext(new MockHttpServletRequest(session, "POST"), null, null);
        DefaultSAML2HandlerRequest request = new DefaultSAML2HandlerRequest(
                context, null, new SAMLDocumentHolder(authnRequest), SAML2Handler.HANDLER_TYPE.IDP);
        DefaultSAML2HandlerResponse response = new DefaultSAML2HandlerResponse();
        handler.handleRequestType(request, response);
        return response;
    }

    public static class ScriptedGenerator implements RoleGenerator {
        static int calls;
        static List<String> next;

        @Override
        public List<String> generateRoles(Principal principal) {
            calls++;
            if (next == null) {
                throw new IllegalStateException("roles were already on the session");
            }
            return next;
        }
    }
}
