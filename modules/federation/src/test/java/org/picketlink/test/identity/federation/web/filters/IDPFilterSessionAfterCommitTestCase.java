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
package org.picketlink.test.identity.federation.web.filters;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.security.Principal;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpSession;

import org.junit.Test;
import org.picketlink.identity.federation.web.filters.IDPFilter;
import org.picketlink.test.identity.federation.web.mock.MockHttpServletRequest;
import org.picketlink.test.identity.federation.web.mock.MockHttpServletResponse;
import org.picketlink.test.identity.federation.web.mock.MockHttpSession;

/**
 * After the IdP has written the SAMLResponse, a later getSession() create is rejected by the
 * container. The filter must keep using a session that already exists.
 */
public class IDPFilterSessionAfterCommitTestCase {

    @Test
    public void committedResponseDoesNotCreateASession() throws Exception {
        TrackingRequest request = new TrackingRequest(null);
        TrackingResponse response = new TrackingResponse(request);
        IDPFilter filter = new IDPFilter();

        filter.doFilter(request, response, new FilterChain() {
            @Override
            public void doFilter(ServletRequest req, ServletResponse res) {
                request.commitAndDropSession();
            }
        });

        assertEquals(0, request.createsAfterCommit);
        assertNull(request.current);
    }

    @Test
    public void openResponseRecordsThePrincipalOnTheExistingSession() throws Exception {
        MockHttpSession session = new MockHttpSession();
        TrackingRequest request = new TrackingRequest(session);
        TrackingResponse response = new TrackingResponse(request);

        new IDPFilter().doFilter(request, response, new FilterChain() {
            @Override
            public void doFilter(ServletRequest req, ServletResponse res) {
            }
        });

        Principal stored = (Principal) session.getAttribute(IDPFilter.SESSION_PARAM_USER_PRINCIPAL);
        assertEquals("testuser", stored.getName());
        assertEquals(0, request.createsAfterCommit);
    }

    private static final class TrackingRequest extends MockHttpServletRequest {
        private HttpSession current;
        private boolean committed;
        private int createsAfterCommit;

        TrackingRequest(HttpSession session) {
            super(session, "POST");
            this.current = session;
        }

        void commitAndDropSession() {
            committed = true;
            current = null;
        }

        @Override
        public HttpSession getSession() {
            return getSession(true);
        }

        @Override
        public HttpSession getSession(boolean create) {
            if (!create) {
                return current;
            }
            if (committed) {
                createsAfterCommit++;
                throw new IllegalStateException("session creation after the response was committed");
            }
            if (current == null) {
                current = new MockHttpSession();
            }
            return current;
        }

        @Override
        public String getRequestURI() {
            return "/sonata/idp/saml/auth";
        }

        @Override
        public String getContextPath() {
            return "/sonata";
        }
    }

    private static final class TrackingResponse extends MockHttpServletResponse {
        private final TrackingRequest request;

        TrackingResponse(TrackingRequest request) {
            this.request = request;
        }

        @Override
        public boolean isCommitted() {
            return request.committed;
        }
    }
}
