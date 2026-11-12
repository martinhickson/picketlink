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
package org.picketlink.test.identity.federation.web.util;

import junit.framework.TestCase;
import org.picketlink.identity.federation.core.saml.v2.holders.DestinationInfoHolder;
import org.picketlink.identity.federation.web.util.PostBindingUtil;
import org.picketlink.test.identity.federation.web.mock.MockHttpServletResponse;

import java.io.ByteArrayOutputStream;

/**
 * RelayState and the form action must not break out of the POST page (CVE-2019-3872).
 */
public class PostBindingHtmlEscapeUnitTestCase extends TestCase {

    public void testRelayStateAndDestinationStayInsideAttributes() throws Exception {
        String payload = "https://idp.example/sso?x=1&y=\"><script>alert(1)</script>";
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        MockHttpServletResponse response = new MockHttpServletResponse();
        response.setOutputStream(out);

        PostBindingUtil.sendPost(new DestinationInfoHolder(payload, "PG5vbmU+", payload), response, true);

        String html = out.toString("UTF-8");
        assertFalse(html.contains("<script"));
        assertTrue(html.contains("ACTION=\"https://idp.example/sso?x=1&amp;y=&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;\""));
        assertTrue(html.contains("NAME=\"RelayState\" VALUE=\"https://idp.example/sso?x=1&amp;y=&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;\""));
        assertTrue(html.contains("NAME=\"SAMLRequest\" VALUE=\"PG5vbmU+\""));
    }

    public void testPlainRelayStateIsUnchanged() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        MockHttpServletResponse response = new MockHttpServletResponse();
        response.setOutputStream(out);

        PostBindingUtil.sendPost(new DestinationInfoHolder("https://sp.example/acs", "YWJj", "https://app.example/return"), response, false);

        String html = out.toString("UTF-8");
        assertTrue(html.contains("ACTION=\"https://sp.example/acs\""));
        assertTrue(html.contains("NAME=\"RelayState\" VALUE=\"https://app.example/return\""));
        assertTrue(html.contains("NAME=\"SAMLResponse\" VALUE=\"YWJj\""));
    }
}
