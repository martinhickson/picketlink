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
package org.picketlink.test.identity.federation.api.saml.v2;

import junit.framework.TestCase;
import org.picketlink.identity.federation.api.util.DeflateUtil;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/**
 * Tests bounded DEFLATE decompression for SAML redirect binding.
 */
public class DeflateBoundsCheckUnitTestCase extends TestCase {

    public void testBoundsCheckEnabledByDefault() {
        assertTrue(DeflateUtil.DEFLATE_BOUNDS_CHECK_ENABLED);
    }

    public void testDefaultMaxInflatedSizeIs128KiB() {
        assertEquals(131072L, DeflateUtil.DEFAULT_MAX_DEFLATE_INFLATED_SIZE);
    }

    public void testNormalMessageWithinDefaultLimit() throws Exception {
        byte[] payload = DeflateUtil.encode(buildPayload(32 * 1024));
        InputStream decoded = DeflateUtil.decode(payload);
        assertEquals(32 * 1024, readFully(decoded).length);
    }

    public void testRejectsInflatedOutputAboveExplicitLimit() throws Exception {
        byte[] payload = DeflateUtil.encode(buildPayload(8 * 1024));
        InputStream decoded = DeflateUtil.decode(payload, 1024);
        try {
            readFully(decoded);
            fail("Expected IOException when inflated output exceeds limit");
        } catch (IOException e) {
            assertTrue(e.getMessage().contains("Maximum SAML DEFLATE inflated size"));
        }
    }

    public void testDefaultDecodeUsesConfiguredLimit() throws Exception {
        byte[] payload = DeflateUtil.encode(buildPayload((int) DeflateUtil.DEFAULT_MAX_DEFLATE_INFLATED_SIZE + 1));
        InputStream decoded = DeflateUtil.decode(payload);
        try {
            readFully(decoded);
            fail("Expected IOException when inflated output exceeds default limit");
        } catch (IOException e) {
            assertTrue(e.getMessage().contains("Maximum SAML DEFLATE inflated size"));
        }
    }

    private static byte[] buildPayload(int size) {
        byte[] payload = new byte[size];
        Arrays.fill(payload, (byte) 'A');
        return payload;
    }

    private static byte[] readFully(InputStream inputStream) throws IOException {
        byte[] buffer = new byte[8192];
        int read;
        int total = 0;
        byte[] result = new byte[0];
        while ((read = inputStream.read(buffer)) != -1) {
            byte[] expanded = Arrays.copyOf(result, total + read);
            System.arraycopy(buffer, 0, expanded, total, read);
            result = expanded;
            total += read;
        }
        return result;
    }
}
