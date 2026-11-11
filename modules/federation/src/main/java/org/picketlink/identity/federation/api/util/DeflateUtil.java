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
package org.picketlink.identity.federation.api.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

/**
 * Encoder of saml messages based on DEFLATE compression
 *
 * @author Anil.Saldhana@redhat.com
 * @since Dec 11, 2008
 */
public final class DeflateUtil {

    /**
     * When {@code true}, SAML redirect-binding DEFLATE decompression is capped at
     * {@link #DEFAULT_MAX_DEFLATE_INFLATED_SIZE} to mitigate zip-bomb DoS (CVE-class).
     */
    public static final boolean DEFLATE_BOUNDS_CHECK_ENABLED = true;

    /**
     * Maximum inflated output size for SAML redirect-binding DEFLATE decoding (128 KiB).
     */
    public static final long DEFAULT_MAX_DEFLATE_INFLATED_SIZE = 131072L;

    private DeflateUtil() {
    }

    /**
     * Apply DEFLATE encoding
     *
     * @param message
     *
     * @return
     *
     * @throws IOException
     */
    public static byte[] encode(byte[] message) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Deflater deflater = new Deflater(Deflater.DEFLATED, true);
        DeflaterOutputStream deflaterStream = new DeflaterOutputStream(baos, deflater);
        deflaterStream.write(message);
        deflaterStream.finish();

        return baos.toByteArray();
    }

    /**
     * Apply DEFLATE encoding
     *
     * @param message
     *
     * @return
     *
     * @throws IOException
     */
    public static byte[] encode(String message) throws IOException {
        return encode(message.getBytes());
    }

    /**
     * DEFLATE decoding for SAML redirect binding.
     */
    public static InputStream decode(byte[] msgToDecode) {
        if (DEFLATE_BOUNDS_CHECK_ENABLED) {
            return decode(msgToDecode, DEFAULT_MAX_DEFLATE_INFLATED_SIZE);
        }
        return decodeUnbounded(msgToDecode);
    }

    /**
     * DEFLATE decoding with an explicit inflated-size cap.
     *
     * @param msgToDecode compressed bytes
     * @param maxInflatedSize maximum allowed inflated output size in bytes
     */
    public static InputStream decode(byte[] msgToDecode, long maxInflatedSize) {
        ByteArrayInputStream bais = new ByteArrayInputStream(msgToDecode);
        return new LimitedInflaterInputStream(bais, maxInflatedSize);
    }

    private static InputStream decodeUnbounded(byte[] msgToDecode) {
        ByteArrayInputStream bais = new ByteArrayInputStream(msgToDecode);
        return new InflaterInputStream(bais, new Inflater(true));
    }

    private static final class LimitedInflaterInputStream extends InputStream {

        private final InflaterInputStream inflaterStream;
        private final Inflater inflater;
        private final long maxInflatedSize;

        private LimitedInflaterInputStream(InputStream inputStream, long maxInflatedSize) {
            this.inflater = new Inflater(true);
            this.inflaterStream = new InflaterInputStream(inputStream, inflater);
            this.maxInflatedSize = maxInflatedSize;
        }

        private void checkMaxInflatedSize() throws IOException {
            if (inflater.getTotalOut() > maxInflatedSize) {
                throw new IOException(String.format(
                        "Maximum SAML DEFLATE inflated size of %d bytes exceeded (decompressed %d bytes)",
                        maxInflatedSize, inflater.getTotalOut()));
            }
        }

        @Override
        public int read() throws IOException {
            int result = inflaterStream.read();
            checkMaxInflatedSize();
            return result;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            int result = inflaterStream.read(buffer, offset, length);
            checkMaxInflatedSize();
            return result;
        }

        @Override
        public int read(byte[] buffer) throws IOException {
            int result = inflaterStream.read(buffer);
            checkMaxInflatedSize();
            return result;
        }

        @Override
        public boolean markSupported() {
            return false;
        }

        @Override
        public void reset() throws IOException {
            throw new IOException("mark/reset not supported");
        }

        @Override
        public void mark(int readlimit) {
        }

        @Override
        public void close() throws IOException {
            inflaterStream.close();
        }

        @Override
        public int available() throws IOException {
            return inflaterStream.available();
        }

        @Override
        public long skip(long n) throws IOException {
            long skipped = inflaterStream.skip(n);
            checkMaxInflatedSize();
            return skipped;
        }
    }
}
