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
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.net.URI;

import javax.xml.datatype.XMLGregorianCalendar;

import org.junit.Before;
import org.junit.Test;
import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.saml.v2.common.IDGenerator;
import org.picketlink.identity.federation.core.saml.v2.util.AssertionUtil;
import org.picketlink.identity.federation.core.saml.v2.util.XMLTimeUtil;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.AudienceRestrictionType;
import org.picketlink.identity.federation.saml.v2.assertion.ConditionsType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.protocol.ResponseType;
import org.picketlink.identity.federation.web.handlers.saml2.SAML2AssertionReplayHandler;

/**
 * Security regression tests for SAML conditions handling: assertion replay protection,
 * time conditions (expiry with clock skew) and audience restriction.
 */
public class SAML2AssertionReplayHandlerTestCase {

    private SAML2AssertionReplayHandler handler;

    @Before
    public void setUp() {
        handler = new SAML2AssertionReplayHandler();
    }

    private static AssertionType assertion(String id, long lifetimeMillis, String audience) throws Exception {
        NameIDType issuer = new NameIDType();
        issuer.setValue("http://idp.example.test");
        AssertionType assertion = AssertionUtil.createAssertion(id, issuer);
        AssertionUtil.createTimedConditions(assertion, lifetimeMillis);
        if (audience != null) {
            AudienceRestrictionType restriction = new AudienceRestrictionType();
            restriction.addAudience(URI.create(audience));
            assertion.getConditions().addCondition(restriction);
        }
        return assertion;
    }

    @Test
    public void rejectsReplayedAssertion() throws Exception {
        AssertionType assertion = assertion(IDGenerator.create("ID_"), 5 * 60 * 1000L, null);
        ResponseType response = new ResponseType(IDGenerator.create("RES_"), XMLTimeUtil.getIssueInstant());
        response.addAssertion(new ResponseType.RTChoiceType(assertion));

        // first consumption records the ID
        consume(response);
        assertEquals(1, handler.trackedIds());

        // replaying the same Response must throw
        try {
            consume(response);
            fail("replayed assertion must be rejected");
        } catch (ProcessingException expected) {
            assertTrue(expected.getMessage().contains("replay"));
        }
    }

    @Test
    public void differentAssertionsAreAccepted() throws Exception {
        consume(responseOf(assertion(IDGenerator.create("ID_"), 5 * 60 * 1000L, null)));
        consume(responseOf(assertion(IDGenerator.create("ID_"), 5 * 60 * 1000L, null)));
        assertEquals(2, handler.trackedIds());
    }

    @Test
    public void expiredAssertionIsDetected() throws Exception {
        AssertionType expired = assertion(IDGenerator.create("ID_"), -60 * 1000L, null);
        // createTimedConditions with negative duration => NotOnOrAfter in the past
        assertTrue("expired assertion must be reported", AssertionUtil.hasExpired(expired));
    }

    @Test
    public void clockSkewForgivesSmallDrift() throws Exception {
        AssertionType nearlyExpired = assertion(IDGenerator.create("ID_"), -2 * 1000L, null);
        // expired by 2s under exact time, valid within a 60s skew window
        assertTrue(AssertionUtil.hasExpired(nearlyExpired));
        assertTrue("60s skew must forgive 2s drift",
                !AssertionUtil.hasExpired(nearlyExpired, 60 * 1000L));
    }

    @Test
    public void audienceRestrictionValidates() throws Exception {
        AssertionType assertion = assertion(IDGenerator.create("ID_"), 5 * 60 * 1000L,
                "https://sp.example.test/acme");
        org.picketlink.config.federation.SPType sp =
                new org.picketlink.config.federation.SPType();
        sp.setServiceURL("https://sp.example.test");
        assertTrue("matching audience must validate",
                AssertionUtil.isAudience(assertion, sp));
    }

    private ResponseType responseOf(AssertionType assertion) throws Exception {
        ResponseType response = new ResponseType(IDGenerator.create("RES_"), XMLTimeUtil.getIssueInstant());
        response.addAssertion(new ResponseType.RTChoiceType(assertion));
        return response;
    }

    private void consume(ResponseType response) throws Exception {
        org.picketlink.identity.federation.core.saml.v2.common.SAMLDocumentHolder holder =
                new org.picketlink.identity.federation.core.saml.v2.common.SAMLDocumentHolder(
                        (org.picketlink.identity.federation.saml.v2.SAML2Object) response);
        org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerRequest request =
                new org.picketlink.identity.federation.core.saml.v2.impl.DefaultSAML2HandlerRequest(
                        null, null, holder,
                        org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2Handler.HANDLER_TYPE.SP);
        handler.handleStatusResponseType(request,
                new org.picketlink.identity.federation.core.saml.v2.impl.DefaultSAML2HandlerResponse());
    }
}
