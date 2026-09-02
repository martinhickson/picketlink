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
package org.picketlink.test.identity.federation.core.parsers.saml;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import org.junit.Test;
import org.picketlink.common.util.DocumentUtil;
import org.picketlink.identity.federation.api.saml.v2.request.SAML2Request;
import org.picketlink.identity.federation.api.saml.v2.response.SAML2Response;
import org.picketlink.identity.federation.core.saml.v2.util.AssertionUtil;
import org.picketlink.identity.federation.core.saml.v2.util.XMLTimeUtil;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.protocol.AuthnRequestType;
import org.picketlink.identity.federation.saml.v2.protocol.LogoutRequestType;
import org.picketlink.identity.federation.saml.v2.protocol.ResponseType;
import org.w3c.dom.Document;

/**
 * Parser/writer round-trip and malformed-input regression tests for the core SAML message
 * set — the thin-coverage area of the StAX parsing layer.
 */
public class SamlParserRoundTripTestCase {

    private static NameIDType issuerOf(String value) {
        NameIDType issuer = new NameIDType();
        issuer.setValue(value);
        return issuer;
    }

    @Test
    public void authnRequestRoundTrip() throws Exception {
        SAML2Request saml2Request = new SAML2Request();
        String id = "authn-rt-1";
        String issuer = "https://sp.example.test";
        AuthnRequestType original = saml2Request.createAuthnRequestType(id, "https://idp.example.test/sso",
                "urn:picketlink:destination", issuer);

        Document document = saml2Request.convert(original);
        String xml = DocumentUtil.asString(document);

        AuthnRequestType reparsed = (AuthnRequestType) new org.picketlink.identity.federation.core.parsers.saml.SAMLParser().parse(
                new ByteArrayInputStream(xml.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        assertEquals(id, reparsed.getID());
        assertEquals(issuer, reparsed.getIssuer().getValue());
    }

    @Test
    public void logoutRequestRoundTrip() throws Exception {
        SAML2Request saml2Request = new SAML2Request();
        String id = "logout-rt-1";
        LogoutRequestType original = saml2Request.createLogoutRequest("https://idp.example.test");

        Document document = saml2Request.convert(original);
        String xml = DocumentUtil.asString(document);

        LogoutRequestType reparsed = (LogoutRequestType) new org.picketlink.identity.federation.core.parsers.saml.SAMLParser().parse(
                new ByteArrayInputStream(xml.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        assertNotNull(reparsed.getID());
    }

    @Test
    public void signedResponseAssertionSurvivesRoundTrip() throws Exception {
        SAML2Response saml2Response = new SAML2Response();
        NameIDType issuer = new NameIDType();
        issuer.setValue("https://idp.example.test");
        AssertionType assertion = AssertionUtil.createAssertion("assertion-rt-1", issuer);
        AssertionUtil.createTimedConditions(assertion, 300000L);

        org.picketlink.identity.federation.core.saml.v2.holders.IssuerInfoHolder issuerHolder =
                new org.picketlink.identity.federation.core.saml.v2.holders.IssuerInfoHolder(issuer);
        ResponseType original = saml2Response.createResponseType("response-rt-1", issuerHolder, assertion);
        Document document = saml2Response.convert(original);
        String xml = DocumentUtil.asString(document);

        Object parsed = new org.picketlink.identity.federation.core.parsers.saml.SAMLParser().parse(
                new ByteArrayInputStream(xml.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        assertTrue(parsed instanceof ResponseType);
        ResponseType reparsed = (ResponseType) parsed;
        assertEquals("response-rt-1", reparsed.getID());
        assertNotNull(reparsed.getAssertions());
        assertEquals(1, reparsed.getAssertions().size());
        assertEquals("assertion-rt-1", reparsed.getAssertions().get(0).getAssertion().getID());
    }

    @Test
    public void malformedXmlIsRejected() throws Exception {
        try {
            new org.picketlink.identity.federation.core.parsers.saml.SAMLParser().parse(new ByteArrayInputStream(
                    "this is not xml at all".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            fail("malformed XML must be rejected");
        } catch (Exception expected) {
            // parser hardening: parse failures surface as exceptions, never null silent passes
        }
    }

    @Test
    public void wrongRootNamespaceIsRejected() throws Exception {
        // well-formed XML, but not a SAML message
        String xml = "<foo:bar xmlns:foo=\"urn:not:saml\"/>";
        Object parsed;
        try {
            parsed = new org.picketlink.identity.federation.core.parsers.saml.SAMLParser().parse(new ByteArrayInputStream(
                    xml.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (Exception expected) {
            return; // rejected outright: acceptable
        }
        if (parsed != null) {
            // if a parser tolerates unknown roots, it must never produce a SAML type
            assertTrue(!(parsed instanceof AuthnRequestType));
        }
    }
}
