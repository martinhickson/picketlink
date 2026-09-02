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
package org.picketlink.identity.federation.web.handlers.saml2;

import java.util.concurrent.ConcurrentHashMap;

import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerRequest;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerResponse;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.protocol.ResponseType;

/**
 * Assertion replay protection: records every assertion ID an SP consumes and rejects any
 * ID presented a second time — the classic SAML response-replay attack class where a
 * captured Response is re-posted to the assertion consumer service. IDs are retained until
 * the corresponding assertion would have expired anyway (retention derived from the
 * assertion's own conditions, clamped to a configurable ceiling).
 *
 * <p>Register in {@code picketlink-handlers.xml} after the signature validation handler:
 *
 * <pre>{@code
 * <Handler class="org.picketlink.identity.federation.web.handlers.saml2.SAML2AssertionReplayHandler" />
 * }</pre>
 */
public class SAML2AssertionReplayHandler extends BaseSAML2Handler {

    /** Maximum retention for IDs whose assertions carry no usable conditions. */
    public static final String MAX_RETENTION_SECONDS_OPTION = "maxRetentionSeconds";

    private static final long DEFAULT_MAX_RETENTION_SECONDS = 24 * 3600L;
    private static final long MIN_RETENTION_SECONDS = 60L;

    private final ConcurrentHashMap<String, Long> consumedIds = new ConcurrentHashMap<String, Long>();
    private volatile long maxRetentionSeconds = DEFAULT_MAX_RETENTION_SECONDS;

    @Override
    public void handleRequestType(SAML2HandlerRequest request, SAML2HandlerResponse response)
            throws ProcessingException {
        // nothing to do for request messages
    }

    private void parseOptions(java.util.Map<String, String> options) {
        if (options != null) {
            String configured = options.get(MAX_RETENTION_SECONDS_OPTION);
            if (configured != null) {
                try {
                    this.maxRetentionSeconds = Math.max(MIN_RETENTION_SECONDS,
                            Long.parseLong(configured.trim()));
                } catch (NumberFormatException ex) {
                    // keep the default retention
                }
            }
        }
    }

    @Override
    public void handleStatusResponseType(SAML2HandlerRequest request, SAML2HandlerResponse response)
            throws ProcessingException {
        if (!(request.getSAML2Object() instanceof ResponseType)) {
            return;
        }
        if (getType() == HANDLER_TYPE.IDP) {
            return;
        }

        ResponseType responseType = (ResponseType) request.getSAML2Object();
        evictExpired();

        if (responseType.getAssertions() != null) {
            for (ResponseType.RTChoiceType assertionChoice : responseType.getAssertions()) {
                AssertionType assertion = assertionChoice.getAssertion();
                if (assertion == null) {
                    continue;
                }
                long retention = retentionSecondsFor(assertion);
                Long previous = consumedIds.putIfAbsent(assertion.getID(),
                        nowSeconds() + retention);
                if (previous != null) {
                    logger.samlHandlerFailedInResponseToVerification("replayed-assertion",
                            assertion.getID());
                    throw new ProcessingException("SAML assertion replay detected for ID "
                            + assertion.getID());
                }
            }
        }
    }

    /** Retention from the assertion's NotOnOrAfter (capped); default cap when unusable. */
    private long retentionSecondsFor(AssertionType assertion) {
        try {
            if (assertion.getConditions() != null
                    && assertion.getConditions().getNotOnOrAfter() != null) {
                long remaining = assertion.getConditions().getNotOnOrAfter()
                        .toGregorianCalendar().getTimeInMillis() / 1000L - nowSeconds();
                if (remaining > 0) {
                    return Math.min(remaining, maxRetentionSeconds());
                }
                return MIN_RETENTION_SECONDS;
            }
        } catch (RuntimeException ex) {
            // fall through to the default cap
        }
        return maxRetentionSeconds();
    }

    long maxRetentionSeconds() {
        return maxRetentionSeconds;
    }

    void evictExpired() {
        long now = nowSeconds();
        // Bounded eviction without a background thread; cheap at ACS rates.
        if (consumedIds.size() < 1024) {
            return;
        }
        for (java.util.Map.Entry<String, Long> entry : consumedIds.entrySet()) {
            if (entry.getValue() <= now) {
                consumedIds.remove(entry.getKey());
            }
        }
    }

    public int trackedIds() {
        return consumedIds.size();
    }

    private static long nowSeconds() {
        return System.currentTimeMillis() / 1000L;
    }
}
