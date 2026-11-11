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
package org.picketlink.test.identity.federation.api.util;

import junit.framework.TestCase;
import org.picketlink.common.util.DocumentUtil;
import org.w3c.dom.Document;

/**
 * XInclude must not be expanded when parsing SAML documents (CVE-2026-10579).
 */
public class XIncludeHardeningUnitTestCase extends TestCase {

    public void testDoesNotExpandXInclude() throws Exception {
        String xml = "<?xml version=\"1.0\"?>"
                + "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\""
                + " xmlns:xi=\"http://www.w3.org/2001/XInclude\">"
                + "<xi:include href=\"file:///etc/passwd\"/>"
                + "</samlp:Response>";
        Document document = DocumentUtil.getDocument(xml);
        String text = document.getDocumentElement().getTextContent();
        if (text != null && text.contains("root:")) {
            fail("XInclude resolved file:///etc/passwd");
        }
    }
}
