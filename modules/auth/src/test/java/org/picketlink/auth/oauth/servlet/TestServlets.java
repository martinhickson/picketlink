package org.picketlink.auth.oauth.servlet;

import java.nio.charset.StandardCharsets;

/** Shared servlet test helpers. */
public final class TestServlets {

    private TestServlets() {
    }

    /** ServletInputStream over fixed form content. */
    public static jakarta.servlet.ServletInputStream body(String content) {
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        return new jakarta.servlet.ServletInputStream() {
            private int position;

            @Override
            public int read() {
                if (position >= bytes.length) {
                    return -1;
                }
                return bytes[position++];
            }

            @Override
            public boolean isFinished() {
                return position >= bytes.length;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(jakarta.servlet.ReadListener listener) {
            }
        };
    }
}
