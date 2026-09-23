package org.picketlink.auth.oauth.servlet;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Arms the token servlet to drop the next POST. The following request proceeds normally.
 */
public final class NextTokenPostFault {

    private final AtomicBoolean armed = new AtomicBoolean();

    public void arm() {
        armed.set(true);
    }

    public boolean consume() {
        return armed.compareAndSet(true, false);
    }
}
